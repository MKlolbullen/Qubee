//! X3DH/PQXDH-style pairwise handshake that produces the
//! `(root_key, peer_initial_dh_pub)` pair the [`crate::sessions`]
//! `DmSession` expects.
//!
//! # Wire shape
//!
//! Two artefacts cross the wire (or the gossipsub topic, or
//! whatever the embedder uses for delivery):
//!
//! 1. [`DmPreKeyBundle`] — published by the *responder*. Contains
//!    their identity public, a freshly-generated X25519 signed
//!    prekey, a freshly-generated ML-KEM-768 prekey, an spk_id
//!    that lets the initiator (and the responder's own state)
//!    distinguish multiple in-flight bundles, a timestamp, and a
//!    hybrid signature over the rest. Both prekeys live until
//!    the responder rotates them; the responder is expected to
//!    keep the matching [`DmPreKeySecrets`] alive for the same
//!    window.
//!
//! 2. [`DmHandshakeInit`] — sent by the *initiator* as the very
//!    first message in a DM session. Carries the initiator's
//!    identity public, a per-handshake X25519 ephemeral, and the
//!    ML-KEM ciphertext from encapsulating against the
//!    responder's `kem_pub`. Echoes which `spk_id`/`spk_pub`
//!    were used so the responder can pick the matching secrets
//!    without scanning every cached SPK. Hybrid-signed under the
//!    initiator's identity.
//!
//! The session-establishment code paths are
//! [`initiate`] and [`respond`]; both produce a 32-byte
//! `root_key` plus the X25519 keypair material the
//! `DoubleRatchet` constructor needs (peer SPK pub for the
//! initiator, own SPK keypair for the responder).
//!
//! # Threat model
//!
//! * **Active man-in-the-middle is detected** by the hybrid
//!   signatures: forging a prekey bundle requires forging
//!   Ed25519 *and* ML-DSA-44 signatures from the responder's
//!   identity. Forging a handshake message similarly requires
//!   compromising the initiator's identity.
//! * **Forward secrecy** at the session level: the X25519
//!   ephemeral is generated per-handshake and dropped after the
//!   responder's view is computed. Compromising a future identity
//!   key doesn't reveal the root_key of past sessions.
//! * **Post-quantum forward secrecy**: the ML-KEM contribution
//!   means a future quantum adversary who breaks X25519 still
//!   needs to break ML-KEM-768 to recover root_key.
//! * **Reply window**: handshake messages older than
//!   [`HANDSHAKE_MAX_AGE_SECS`] are rejected by `respond` so a
//!   captured message can't be replayed indefinitely.
//!
//! # Deviations from full Signal X3DH/PQXDH
//!
//! Signal's X3DH includes a `DH(IK_a, SPK_b)` leg that
//! cryptographically binds the SPK to the initiator's identity
//! independently of the message-level signature. Qubee's
//! [`crate::identity::IdentityKey`] is signing-only (Ed25519 +
//! ML-DSA-44 hybrid) — it carries no X25519 portion that could
//! serve as a DH endpoint. Adding a long-lived "identity
//! agreement key" alongside the signing identity would close the
//! gap; for now the binding is provided by the message-level
//! `HybridSignature` over the handshake init, which the
//! responder verifies against the initiator's published
//! `IdentityKey` before deriving the root_key.
//!
//! No one-time prekeys (OPKs). Adding them would tighten
//! forward secrecy against an SPK-private compromise but adds
//! storage + rotation logic. SPK is currently single-use *per
//! peer* in practice — if two distinct initiators contact the
//! same responder before SPK rotation, both will share an
//! `peer_initial_dh_pub`, which the DH ratchet steps past on
//! the first response. Rotating SPKs frequently is the operator
//! mitigation; OPK-style single-use prekeys would be the
//! protocol mitigation.

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as KyberPublicKeyTrait, SecretKey as KyberSecretKeyTrait,
    SharedSecret as _,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey as DhPublicKey, StaticSecret as DhStaticSecret};

use crate::identity::identity_key::{
    HybridSignature, IdentityId, IdentityKey, IdentityKeyPair,
};

/// Reject handshake init messages older than this. 5 minutes
/// matches the rest of the protocol's freshness window.
pub const HANDSHAKE_MAX_AGE_SECS: u64 = 5 * 60;

/// Domain-separated context for the canonical-bytes serialisers.
const PREKEY_BUNDLE_TAG: &[u8] = b"qubee/dm-handshake/v1/prekey-bundle";
const HANDSHAKE_INIT_TAG: &[u8] = b"qubee/dm-handshake/v1/init";
/// HKDF info string for `(dh_output || kem_ss) → root_key`.
const ROOT_KEY_INFO: &[u8] = b"qubee/dm-handshake/v1/root";

/// Public prekey bundle published by the responder. Both prekeys
/// (X25519 SPK + ML-KEM SPK) are signed by the responder's
/// identity so the initiator can verify the bundle came from the
/// claimed identity before encapsulating against it.
#[derive(Clone, Debug)]
pub struct DmPreKeyBundle {
    /// Responder's hybrid-signing identity public.
    pub identity: IdentityKey,
    /// X25519 signed-prekey public. Becomes `peer_initial_dh_pub`
    /// for the initiator's `DoubleRatchet::initiator` call;
    /// becomes `own_initial_keypair`'s public for the
    /// responder's `DoubleRatchet::responder` call.
    pub spk_pub: DhPublicKey,
    /// ML-KEM-768 public key the initiator encapsulates against.
    pub kem_pub: mlkem768::PublicKey,
    /// Responder-controlled rotation counter. Lets the
    /// responder maintain multiple in-flight bundles (e.g.
    /// post-rotation grace period) and lets the initiator echo
    /// back which one they picked.
    pub spk_id: u32,
    /// Wall-clock seconds when the bundle was generated. Older
    /// bundles can be rejected by the embedder; this layer
    /// itself doesn't enforce a max age on bundles (only on
    /// handshake messages).
    pub timestamp: u64,
    /// Hybrid signature over `canonical_prekey_bundle_bytes`.
    pub signature: HybridSignature,
}

/// Private halves of a [`DmPreKeyBundle`]. The responder keeps
/// these alive for the same window the bundle is published.
/// `spk_priv` is what feeds into `DoubleRatchet::responder`'s
/// `own_initial_keypair`; `kem_secret_bytes` is what
/// `mlkem768::decapsulate` operates on.
#[derive(Clone)]
pub struct DmPreKeySecrets {
    pub spk_priv: DhStaticSecret,
    pub kem_secret_bytes: Vec<u8>,
    pub spk_id: u32,
}

/// First handshake message the initiator sends to the responder.
/// Carries everything the responder needs to recover the same
/// `root_key` the initiator just derived.
#[derive(Clone, Debug)]
pub struct DmHandshakeInit {
    /// Initiator's hybrid-signing identity public.
    pub initiator_identity: IdentityKey,
    /// Per-handshake X25519 ephemeral public. NOT the initiator's
    /// first ratchet send key (which is generated inside
    /// `DoubleRatchet::initiator`); just the X25519 leg of the
    /// X3DH-style key derivation.
    pub ephemeral_pub: DhPublicKey,
    /// ML-KEM-768 ciphertext encapsulating against the
    /// responder's `kem_pub`.
    pub kem_ciphertext: Vec<u8>,
    /// Which prekey bundle this handshake refers to. Echoes the
    /// responder's `spk_id` for symmetry with later rotation.
    pub used_spk_id: u32,
    /// The exact 32 bytes of the SPK pub the initiator used.
    /// Lets the responder pick the right secrets in O(1) from a
    /// per-spk-id map without comparing two pubs at the
    /// application layer.
    pub used_spk_pub: DhPublicKey,
    /// Wall-clock seconds when the handshake message was built.
    pub timestamp: u64,
    /// Hybrid signature over `canonical_handshake_init_bytes`.
    pub signature: HybridSignature,
}

/// Bincode-friendly wire representation of [`DmPreKeyBundle`].
/// `IdentityKey` and `HybridSignature` already have manual
/// `Serialize`/`Deserialize` impls; we serialise the X25519 +
/// ML-KEM bytes directly because neither type has a serde
/// derivation we can rely on.
#[derive(Serialize, Deserialize)]
struct DmPreKeyBundleWire {
    identity: IdentityKey,
    spk_pub: [u8; 32],
    kem_pub: Vec<u8>,
    spk_id: u32,
    timestamp: u64,
    signature: HybridSignature,
}

/// Bincode-friendly wire representation of [`DmHandshakeInit`].
#[derive(Serialize, Deserialize)]
struct DmHandshakeInitWire {
    initiator_identity: IdentityKey,
    ephemeral_pub: [u8; 32],
    kem_ciphertext: Vec<u8>,
    used_spk_id: u32,
    used_spk_pub: [u8; 32],
    timestamp: u64,
    signature: HybridSignature,
}

impl DmPreKeyBundle {
    /// Serialize to bincode bytes for transport (e.g. embedded
    /// in a contact-add QR / shared via signalling channel).
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let wire = DmPreKeyBundleWire {
            identity: self.identity.clone(),
            spk_pub: *self.spk_pub.as_bytes(),
            kem_pub: self.kem_pub.as_bytes().to_vec(),
            spk_id: self.spk_id,
            timestamp: self.timestamp,
            signature: self.signature.clone(),
        };
        bincode::serialize(&wire).context("DmPreKeyBundle serialize")
    }

    /// Deserialize from bytes produced by [`to_wire`].
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let wire: DmPreKeyBundleWire =
            bincode::deserialize(bytes).context("DmPreKeyBundle deserialize")?;
        let kem_pub = mlkem768::PublicKey::from_bytes(&wire.kem_pub)
            .map_err(|e| anyhow!("invalid kem_pub on wire: {e}"))?;
        Ok(Self {
            identity: wire.identity,
            spk_pub: DhPublicKey::from(wire.spk_pub),
            kem_pub,
            spk_id: wire.spk_id,
            timestamp: wire.timestamp,
            signature: wire.signature,
        })
    }
}

impl DmHandshakeInit {
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let wire = DmHandshakeInitWire {
            initiator_identity: self.initiator_identity.clone(),
            ephemeral_pub: *self.ephemeral_pub.as_bytes(),
            kem_ciphertext: self.kem_ciphertext.clone(),
            used_spk_id: self.used_spk_id,
            used_spk_pub: *self.used_spk_pub.as_bytes(),
            timestamp: self.timestamp,
            signature: self.signature.clone(),
        };
        bincode::serialize(&wire).context("DmHandshakeInit serialize")
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let wire: DmHandshakeInitWire =
            bincode::deserialize(bytes).context("DmHandshakeInit deserialize")?;
        Ok(Self {
            initiator_identity: wire.initiator_identity,
            ephemeral_pub: DhPublicKey::from(wire.ephemeral_pub),
            kem_ciphertext: wire.kem_ciphertext,
            used_spk_id: wire.used_spk_id,
            used_spk_pub: DhPublicKey::from(wire.used_spk_pub),
            timestamp: wire.timestamp,
            signature: wire.signature,
        })
    }
}

impl DmPreKeySecrets {
    /// Bytes for keystore persistence. Round-trips through
    /// [`DmPreKeySecrets::restore`]. The contained material is
    /// secret — caller is expected to encrypt at rest, which
    /// `SecureKeyStore::store_key` does.
    pub fn persist(&self) -> Result<Vec<u8>> {
        #[derive(Serialize, Deserialize)]
        struct PersistedSecrets {
            spk_priv: [u8; 32],
            kem_secret_bytes: Vec<u8>,
            spk_id: u32,
        }
        let p = PersistedSecrets {
            spk_priv: self.spk_priv.to_bytes(),
            kem_secret_bytes: self.kem_secret_bytes.clone(),
            spk_id: self.spk_id,
        };
        bincode::serialize(&p).context("DmPreKeySecrets serialize")
    }

    pub fn restore(bytes: &[u8]) -> Result<Self> {
        #[derive(Serialize, Deserialize)]
        struct PersistedSecrets {
            spk_priv: [u8; 32],
            kem_secret_bytes: Vec<u8>,
            spk_id: u32,
        }
        let p: PersistedSecrets =
            bincode::deserialize(bytes).context("DmPreKeySecrets deserialize")?;
        Ok(Self {
            spk_priv: DhStaticSecret::from(p.spk_priv),
            kem_secret_bytes: p.kem_secret_bytes,
            spk_id: p.spk_id,
        })
    }
}

/// Result of the initiator's [`initiate`] call.
pub struct InitiateOutcome {
    /// 32-byte symmetric secret to feed into
    /// `DoubleRatchet::initiator` / `_hybrid` as `root_key`.
    pub root_key: [u8; 32],
    /// X25519 public to feed into `DoubleRatchet::initiator` as
    /// `peer_initial_dh_pub`. Equals `peer_bundle.spk_pub`.
    pub peer_initial_dh_pub: DhPublicKey,
    /// Wire message to send to the responder.
    pub message: DmHandshakeInit,
}

/// Result of the responder's [`respond`] call.
pub struct RespondOutcome {
    /// Same root_key the initiator computed.
    pub root_key: [u8; 32],
    /// X25519 keypair to move into `DoubleRatchet::responder`'s
    /// `own_initial_keypair`. Materially equals
    /// `prekey_secrets.spk_priv`; we surface it as a fresh
    /// `StaticSecret` so the caller doesn't have to round-trip
    /// through bytes.
    pub own_initial_keypair: DhStaticSecret,
    /// `IdentityId` of the initiator, lifted from the verified
    /// `DmHandshakeInit.initiator_identity`. The session
    /// manager keys sessions on this id.
    pub peer_id: IdentityId,
}

/// Generate a fresh prekey bundle for advertising. Caller is
/// responsible for distributing the public bundle (e.g.
/// publishing to a directory, embedding in a contact-add QR
/// code) and persisting the secrets alongside the bundle's
/// `spk_id` for as long as the bundle is published.
pub fn generate_prekey_bundle(
    identity_kp: &IdentityKeyPair,
    spk_id: u32,
) -> Result<(DmPreKeyBundle, DmPreKeySecrets)> {
    let spk_priv = DhStaticSecret::random_from_rng(thread_rng());
    let spk_pub = DhPublicKey::from(&spk_priv);
    let (kem_pub, kem_secret) = mlkem768::keypair();
    let timestamp = now_secs()?;

    let canonical = canonical_prekey_bundle_bytes(
        &identity_kp.public_key(),
        &spk_pub,
        kem_pub.as_bytes(),
        spk_id,
        timestamp,
    );
    let signature = identity_kp
        .sign(&canonical)
        .context("sign prekey bundle")?;

    let bundle = DmPreKeyBundle {
        identity: identity_kp.public_key(),
        spk_pub,
        kem_pub,
        spk_id,
        timestamp,
        signature,
    };
    let secrets = DmPreKeySecrets {
        spk_priv,
        kem_secret_bytes: kem_secret.as_bytes().to_vec(),
        spk_id,
    };
    Ok((bundle, secrets))
}

/// Initiator side. Verifies the responder's bundle signature,
/// generates a per-handshake X25519 ephemeral, encapsulates
/// against the responder's ML-KEM pub, derives the shared
/// `root_key` from `(dh || kem_ss)`, signs the handshake
/// message under our identity, and returns everything the
/// caller needs to (a) feed `DoubleRatchet::initiator` and
/// (b) transmit the handshake message to the peer.
pub fn initiate(
    own_identity_kp: &IdentityKeyPair,
    peer_bundle: &DmPreKeyBundle,
) -> Result<InitiateOutcome> {
    let canonical = canonical_prekey_bundle_bytes(
        &peer_bundle.identity,
        &peer_bundle.spk_pub,
        peer_bundle.kem_pub.as_bytes(),
        peer_bundle.spk_id,
        peer_bundle.timestamp,
    );
    let valid = peer_bundle
        .identity
        .verify(&canonical, &peer_bundle.signature)
        .context("verify peer bundle signature")?;
    if !valid {
        return Err(anyhow!("peer prekey bundle signature failed verification"));
    }

    let ek_priv = DhStaticSecret::random_from_rng(thread_rng());
    let ek_pub = DhPublicKey::from(&ek_priv);

    let (kem_ss, kem_ct) = mlkem768::encapsulate(&peer_bundle.kem_pub);
    let dh = ek_priv.diffie_hellman(&peer_bundle.spk_pub);
    let root_key = combine_secrets(dh.as_bytes(), kem_ss.as_bytes())?;

    let timestamp = now_secs()?;
    let canonical_msg = canonical_handshake_init_bytes(
        &own_identity_kp.public_key(),
        &ek_pub,
        kem_ct.as_bytes(),
        peer_bundle.spk_id,
        &peer_bundle.spk_pub,
        timestamp,
    );
    let signature = own_identity_kp
        .sign(&canonical_msg)
        .context("sign handshake init")?;

    let message = DmHandshakeInit {
        initiator_identity: own_identity_kp.public_key(),
        ephemeral_pub: ek_pub,
        kem_ciphertext: kem_ct.as_bytes().to_vec(),
        used_spk_id: peer_bundle.spk_id,
        used_spk_pub: peer_bundle.spk_pub,
        timestamp,
        signature,
    };

    Ok(InitiateOutcome {
        root_key,
        peer_initial_dh_pub: peer_bundle.spk_pub,
        message,
    })
}

/// Responder side. Verifies the handshake init's signature
/// under the claimed initiator identity, checks the freshness
/// window, sanity-checks that the `spk_id` / `spk_pub` echoed
/// back match the secrets the caller produced, decapsulates the
/// ML-KEM ciphertext, computes the same DH leg, derives the
/// matching `root_key`, and surfaces the keypair material the
/// `DoubleRatchet::responder` constructor wants.
pub fn respond(
    prekey_secrets: &DmPreKeySecrets,
    handshake_msg: &DmHandshakeInit,
) -> Result<RespondOutcome> {
    let canonical = canonical_handshake_init_bytes(
        &handshake_msg.initiator_identity,
        &handshake_msg.ephemeral_pub,
        &handshake_msg.kem_ciphertext,
        handshake_msg.used_spk_id,
        &handshake_msg.used_spk_pub,
        handshake_msg.timestamp,
    );
    let valid = handshake_msg
        .initiator_identity
        .verify_with_max_age(
            &canonical,
            &handshake_msg.signature,
            HANDSHAKE_MAX_AGE_SECS,
        )
        .context("verify handshake init signature")?;
    if !valid {
        return Err(anyhow!(
            "handshake init signature failed verification or message expired"
        ));
    }

    if handshake_msg.used_spk_id != prekey_secrets.spk_id {
        return Err(anyhow!(
            "handshake refers to spk_id {} but secrets cover {}",
            handshake_msg.used_spk_id,
            prekey_secrets.spk_id,
        ));
    }
    let expected_spk_pub = DhPublicKey::from(&prekey_secrets.spk_priv);
    if handshake_msg.used_spk_pub.as_bytes() != expected_spk_pub.as_bytes() {
        return Err(anyhow!(
            "handshake's used_spk_pub doesn't match local prekey secrets"
        ));
    }

    let ct = mlkem768::Ciphertext::from_bytes(&handshake_msg.kem_ciphertext)
        .map_err(|e| anyhow!("invalid ML-KEM ciphertext: {e}"))?;
    let sk = mlkem768::SecretKey::from_bytes(&prekey_secrets.kem_secret_bytes)
        .map_err(|e| anyhow!("invalid persisted ML-KEM secret: {e}"))?;
    let kem_ss = mlkem768::decapsulate(&ct, &sk);

    let dh = prekey_secrets
        .spk_priv
        .diffie_hellman(&handshake_msg.ephemeral_pub);
    let root_key = combine_secrets(dh.as_bytes(), kem_ss.as_bytes())?;

    let own_initial_keypair = DhStaticSecret::from(prekey_secrets.spk_priv.to_bytes());
    Ok(RespondOutcome {
        root_key,
        own_initial_keypair,
        peer_id: handshake_msg.initiator_identity.identity_id,
    })
}

/// HKDF over `(dh || kem_ss)` → 32-byte root key. Matches
/// PQXDH's "concatenate, hash, truncate" pattern. Salt is zero
/// (no extract step seed); domain separation comes from the
/// info string.
fn combine_secrets(dh_output: &[u8], kem_ss: &[u8]) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(dh_output.len() + kem_ss.len());
    ikm.extend_from_slice(dh_output);
    ikm.extend_from_slice(kem_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(ROOT_KEY_INFO, &mut out)
        .map_err(|e| anyhow!("hkdf expand (handshake root): {e}"))?;
    Ok(out)
}

/// Canonical bytes the prekey bundle's [`HybridSignature`]
/// covers. Hand-rolled (not bincode) so signatures stay stable
/// across struct field reordering or future serde tweaks.
fn canonical_prekey_bundle_bytes(
    identity: &IdentityKey,
    spk_pub: &DhPublicKey,
    kem_pub_bytes: &[u8],
    spk_id: u32,
    timestamp: u64,
) -> Vec<u8> {
    let mut h = Hasher::new();
    h.update(PREKEY_BUNDLE_TAG);
    h.update(&[0u8]);
    h.update(identity.identity_id.as_ref());
    h.update(&[0u8]);
    h.update(spk_pub.as_bytes());
    h.update(&[0u8]);
    h.update(&(kem_pub_bytes.len() as u32).to_le_bytes());
    h.update(kem_pub_bytes);
    h.update(&[0u8]);
    h.update(&spk_id.to_le_bytes());
    h.update(&[0u8]);
    h.update(&timestamp.to_le_bytes());
    h.finalize().as_bytes().to_vec()
}

/// Canonical bytes the handshake-init's [`HybridSignature`] covers.
fn canonical_handshake_init_bytes(
    initiator_identity: &IdentityKey,
    ephemeral_pub: &DhPublicKey,
    kem_ct_bytes: &[u8],
    used_spk_id: u32,
    used_spk_pub: &DhPublicKey,
    timestamp: u64,
) -> Vec<u8> {
    let mut h = Hasher::new();
    h.update(HANDSHAKE_INIT_TAG);
    h.update(&[0u8]);
    h.update(initiator_identity.identity_id.as_ref());
    h.update(&[0u8]);
    h.update(ephemeral_pub.as_bytes());
    h.update(&[0u8]);
    h.update(&(kem_ct_bytes.len() as u32).to_le_bytes());
    h.update(kem_ct_bytes);
    h.update(&[0u8]);
    h.update(&used_spk_id.to_le_bytes());
    h.update(&[0u8]);
    h.update(used_spk_pub.as_bytes());
    h.update(&[0u8]);
    h.update(&timestamp.to_le_bytes());
    h.finalize().as_bytes().to_vec()
}

fn now_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| anyhow!("system time before epoch: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DoubleRatchet;
    use crate::sessions::{DmSession, SessionManager};

    fn fresh_identity() -> IdentityKeyPair {
        IdentityKeyPair::generate().expect("identity")
    }

    #[test]
    fn handshake_round_trip_yields_matching_root_key() {
        let alice = fresh_identity();
        let bob = fresh_identity();

        // Bob publishes a prekey bundle.
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(&bob, 1).unwrap();
        // Alice initiates.
        let init_outcome = initiate(&alice, &bob_bundle).expect("initiate");
        // Bob responds.
        let resp_outcome = respond(&bob_secrets, &init_outcome.message).expect("respond");

        // Both compute the same root_key.
        assert_eq!(init_outcome.root_key, resp_outcome.root_key);
        // Responder's own_initial_keypair pub matches what Alice
        // saw as `peer_initial_dh_pub`.
        assert_eq!(
            DhPublicKey::from(&resp_outcome.own_initial_keypair).as_bytes(),
            init_outcome.peer_initial_dh_pub.as_bytes()
        );
        // Responder identifies the peer correctly.
        assert_eq!(resp_outcome.peer_id, alice.identity_id());
    }

    #[test]
    fn handshake_root_key_drives_double_ratchet_session() {
        // The point of the handshake. Both sides take their
        // half of the outcome and feed it straight into the DR
        // primitive — the resulting sessions exchange messages
        // cleanly without any further coordination.
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(&bob, 7).unwrap();
        let init_out = initiate(&alice, &bob_bundle).unwrap();
        let resp_out = respond(&bob_secrets, &init_out.message).unwrap();

        let mut alice_dr =
            DoubleRatchet::initiator(&init_out.root_key, init_out.peer_initial_dh_pub).unwrap();
        let mut bob_dr =
            DoubleRatchet::responder(&resp_out.root_key, resp_out.own_initial_keypair).unwrap();

        let w = alice_dr.encrypt(b"hi bob", b"").unwrap();
        assert_eq!(bob_dr.decrypt(&w, b"").unwrap(), b"hi bob");
        let w = bob_dr.encrypt(b"hi alice", b"").unwrap();
        assert_eq!(alice_dr.decrypt(&w, b"").unwrap(), b"hi alice");
    }

    #[test]
    fn handshake_drives_session_manager_dm_round_trip() {
        // Same as above but routed through the SessionManager
        // surface — exercises the full path the JNI bridge will
        // use end-to-end (handshake → establish_initiator/
        // responder → encrypt/decrypt).
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(&bob, 1).unwrap();
        let init_out = initiate(&alice, &bob_bundle).unwrap();
        let resp_out = respond(&bob_secrets, &init_out.message).unwrap();

        let mut alice_sm = SessionManager::new();
        alice_sm
            .establish_initiator(
                bob.identity_id(),
                &init_out.root_key,
                init_out.peer_initial_dh_pub,
            )
            .unwrap();
        let mut bob_sm = SessionManager::new();
        bob_sm
            .establish_responder(
                resp_out.peer_id,
                &resp_out.root_key,
                resp_out.own_initial_keypair,
            )
            .unwrap();

        let w = alice_sm
            .encrypt(&bob.identity_id(), b"first dm", b"")
            .unwrap();
        assert_eq!(
            bob_sm.decrypt(&alice.identity_id(), &w, b"").unwrap(),
            b"first dm"
        );
        let w = bob_sm
            .encrypt(&alice.identity_id(), b"reply", b"")
            .unwrap();
        assert_eq!(
            alice_sm.decrypt(&bob.identity_id(), &w, b"").unwrap(),
            b"reply"
        );
        // Drop unused warnings on the two helper-imported types.
        let _ = std::any::type_name::<DmSession>();
    }

    #[test]
    fn rejects_tampered_prekey_bundle() {
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (mut bundle, _secrets) = generate_prekey_bundle(&bob, 1).unwrap();
        // Tamper the SPK pub — sig should now fail.
        bundle.spk_pub = DhPublicKey::from(&DhStaticSecret::random_from_rng(thread_rng()));
        assert!(initiate(&alice, &bundle).is_err());
    }

    #[test]
    fn rejects_handshake_with_wrong_spk_id() {
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bundle_v1, secrets_v1) = generate_prekey_bundle(&bob, 1).unwrap();
        // Initiator handshakes against bundle v1 — message
        // carries used_spk_id = 1.
        let init_out = initiate(&alice, &bundle_v1).unwrap();
        // Responder rotates: secrets_v2 only covers spk_id=2.
        let (_bundle_v2, secrets_v2) = generate_prekey_bundle(&bob, 2).unwrap();
        // Responding with secrets_v2 against an init that
        // referenced spk_id=1 is rejected.
        assert!(respond(&secrets_v2, &init_out.message).is_err());
        // But the original secrets still work.
        respond(&secrets_v1, &init_out.message).expect("v1 secrets accept");
    }

    #[test]
    fn rejects_handshake_with_mismatched_spk_pub() {
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bundle, _secrets) = generate_prekey_bundle(&bob, 1).unwrap();
        let init_out = initiate(&alice, &bundle).unwrap();
        // Construct fake "secrets" that claim the same spk_id
        // but cover a different X25519 keypair.
        let fake_priv = DhStaticSecret::random_from_rng(thread_rng());
        let (_kem_pub, kem_secret) = mlkem768::keypair();
        let fake_secrets = DmPreKeySecrets {
            spk_priv: fake_priv,
            kem_secret_bytes: kem_secret.as_bytes().to_vec(),
            spk_id: 1,
        };
        assert!(respond(&fake_secrets, &init_out.message).is_err());
    }

    #[test]
    fn rejects_expired_handshake() {
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bundle, secrets) = generate_prekey_bundle(&bob, 1).unwrap();
        let mut init_out = initiate(&alice, &bundle).unwrap();
        // Backdate the handshake's signature timestamp past
        // HANDSHAKE_MAX_AGE_SECS. verify_with_max_age sees this
        // and rejects without ever reaching the cryptography
        // (matches the existing pattern in group_message.rs).
        init_out.message.signature.timestamp = init_out
            .message
            .signature
            .timestamp
            .saturating_sub(HANDSHAKE_MAX_AGE_SECS + 60);
        assert!(respond(&secrets, &init_out.message).is_err());
    }

    #[test]
    fn wire_round_trip_bundle_and_handshake() {
        // Both wire helpers round-trip without losing
        // signature-validating bytes — crucial for the JNI
        // bridge, which carries these structs as opaque byte[]s.
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bundle, secrets) = generate_prekey_bundle(&bob, 42).unwrap();

        let wire = bundle.to_wire().unwrap();
        let restored = DmPreKeyBundle::from_wire(&wire).unwrap();
        // Initiating against the restored bundle still produces
        // a valid handshake (sig still verifies, keys still
        // line up).
        let init_out = initiate(&alice, &restored).unwrap();

        let msg_wire = init_out.message.to_wire().unwrap();
        let restored_msg = DmHandshakeInit::from_wire(&msg_wire).unwrap();
        let resp_out = respond(&secrets, &restored_msg).unwrap();
        assert_eq!(init_out.root_key, resp_out.root_key);

        // Secret persistence round-trip.
        let s_wire = secrets.persist().unwrap();
        let restored_secrets = DmPreKeySecrets::restore(&s_wire).unwrap();
        let resp_again = respond(&restored_secrets, &restored_msg).unwrap();
        assert_eq!(resp_again.root_key, resp_out.root_key);
    }

    #[test]
    fn distinct_handshakes_yield_distinct_root_keys() {
        // Forward-secrecy proxy: two consecutive initiators
        // against the same bundle produce different
        // ephemeral X25519 keys → different DH outputs →
        // different root_keys.
        let alice = fresh_identity();
        let bob = fresh_identity();
        let (bundle, _secrets) = generate_prekey_bundle(&bob, 1).unwrap();
        let one = initiate(&alice, &bundle).unwrap();
        let two = initiate(&alice, &bundle).unwrap();
        assert_ne!(one.root_key, two.root_key);
    }
}
