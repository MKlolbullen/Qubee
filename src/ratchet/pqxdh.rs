//! PQXDH — post-quantum, deniable initial key agreement.
//!
//! An X3DH-style handshake (Perrin/Marlinspike) extended with an
//! ML-KEM-768 encapsulation, à la Signal's PQXDH. It establishes the
//! 32-byte shared secret that seeds a [`super::double_ratchet::DoubleRatchet`].
//!
//! ## Why this shape
//!
//! * **Deniable.** The shared secret is derived from Diffie-Hellman
//!   outputs where *each party holds one private key of every pair* —
//!   so either could have computed the secret, and a transcript proves
//!   nothing about who authored the resulting messages. No message is
//!   signed with a long-term key. (The prekey *bundle* may be signed by
//!   the publisher to bind the keys to an identity — that only attests
//!   "I published these prekeys", not "I sent this message". Bundle
//!   signing is the caller's responsibility, layered on top with the
//!   existing hybrid identity signature.)
//! * **Post-quantum.** In addition to the classical DHs, the initiator
//!   encapsulates to the responder's ML-KEM-768 prekey; the KEM shared
//!   secret is folded into the KDF. A network adversary recording
//!   today's handshake cannot recover the session key with a future
//!   quantum computer ("harvest now, decrypt later" resistance) unless
//!   it also breaks ML-KEM.
//!
//! ## Roles
//!
//! * **Bob (responder)** publishes a prekey bundle:
//!   identity X25519, a signed-prekey X25519 (`spk`, which doubles as
//!   his initial ratchet public), an optional one-time X25519 prekey
//!   (`opk`), and an ML-KEM-768 prekey.
//! * **Alice (initiator)** fetches the bundle, generates an ephemeral
//!   X25519 (`ek`), computes the DHs + KEM, and derives `sk`. She sends
//!   Bob an initial message carrying her identity public, `ek` public,
//!   and the KEM ciphertext.
//! * **Bob** reproduces the same `sk` from his private keys + the
//!   ciphertext.

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768::{
    decapsulate as kem_decapsulate, encapsulate as kem_encapsulate, keypair as kem_keypair,
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::security::secure_rng;

const PQXDH_KDF_INFO: &[u8] = b"qubee_pqxdh_v1";

/// Bob's secret prekey material. Held on the responder's device.
pub struct PrekeyBundleSecret {
    /// Long-term identity DH key (X25519). Distinct from the Ed25519 /
    /// ML-DSA *signing* identity — this one is for the deniable DH.
    pub identity: StaticSecret,
    /// Signed prekey (medium-term). Doubles as Bob's initial ratchet
    /// key: its public is what Alice hands to `DoubleRatchet::init_alice`
    /// and its secret is what Bob hands to `init_bob`.
    pub signed_prekey: StaticSecret,
    /// Optional one-time prekey (single use — deleted after a handshake
    /// consumes it, which is what makes the very first message forward-
    /// secret even before the first ratchet step).
    pub one_time_prekey: Option<StaticSecret>,
    /// ML-KEM-768 prekey secret.
    pub kem_secret: KemSecretKey,
}

impl PrekeyBundleSecret {
    /// Generate a fresh bundle (with a one-time prekey).
    pub fn generate() -> Result<Self> {
        let (_kem_pk, kem_secret) = kem_keypair();
        Ok(PrekeyBundleSecret {
            identity: random_secret()?,
            signed_prekey: random_secret()?,
            one_time_prekey: Some(random_secret()?),
            kem_secret,
        })
    }

    /// The publishable public half, given the retained KEM public key
    /// bytes (the KEM secret can't reproduce its public, so the caller
    /// keeps it from `generate_with_public`).
    pub fn public_with_kem(&self, kem_public: KemPublicKey) -> PrekeyBundlePublic {
        PrekeyBundlePublic {
            identity: PublicKey::from(&self.identity),
            signed_prekey: PublicKey::from(&self.signed_prekey),
            one_time_prekey: self.one_time_prekey.as_ref().map(PublicKey::from),
            kem_public,
        }
    }
}

/// Bob's public prekey bundle, as fetched by Alice. In a full
/// deployment this is signed by Bob's hybrid identity key (by the
/// caller) so Alice can verify authenticity before using it.
#[derive(Clone)]
pub struct PrekeyBundlePublic {
    pub identity: PublicKey,
    pub signed_prekey: PublicKey,
    pub one_time_prekey: Option<PublicKey>,
    pub kem_public: KemPublicKey,
}

/// The initial message Alice sends Bob so he can reproduce `sk`.
#[derive(Clone)]
pub struct InitialMessage {
    /// Alice's identity DH public.
    pub identity: PublicKey,
    /// Alice's ephemeral DH public.
    pub ephemeral: PublicKey,
    /// ML-KEM ciphertext encapsulated to Bob's KEM prekey.
    pub kem_ciphertext: KemCiphertext,
    /// Whether Alice consumed Bob's one-time prekey (so Bob knows to
    /// include it in his DH set + delete it).
    pub used_one_time_prekey: bool,
}

/// Serialisable form of an [`InitialMessage`]. The X25519 publics and
/// the ML-KEM ciphertext aren't serde-native, so the on-wire encoding
/// round-trips through this byte mirror. Carries only public handshake
/// material (no secrets), so — unlike ratchet/session state — it is safe
/// to place on the wire.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct WireInitialMessage {
    pub identity: [u8; 32],
    pub ephemeral: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub used_one_time_prekey: bool,
}

impl WireInitialMessage {
    pub fn from_message(m: &InitialMessage) -> Self {
        WireInitialMessage {
            identity: *m.identity.as_bytes(),
            ephemeral: *m.ephemeral.as_bytes(),
            kem_ciphertext: m.kem_ciphertext.as_bytes().to_vec(),
            used_one_time_prekey: m.used_one_time_prekey,
        }
    }

    pub fn to_message(&self) -> Result<InitialMessage> {
        Ok(InitialMessage {
            identity: PublicKey::from(self.identity),
            ephemeral: PublicKey::from(self.ephemeral),
            kem_ciphertext: KemCiphertext::from_bytes(&self.kem_ciphertext)
                .map_err(|e| anyhow!("invalid KEM ciphertext: {e}"))?,
            used_one_time_prekey: self.used_one_time_prekey,
        })
    }
}

/// Result of the initiator handshake.
pub struct PqxdhInitiatorResult {
    /// The 32-byte shared secret seeding the ratchet.
    pub shared_secret: [u8; 32],
    /// The initial message to send Bob.
    pub initial_message: InitialMessage,
    /// Bob's ratchet public (his signed prekey) — feed to
    /// `DoubleRatchet::init_alice`.
    pub bob_ratchet_public: PublicKey,
}

/// Run the initiator (Alice) side. `alice_identity` is Alice's
/// long-term X25519 identity secret; `bundle` is Bob's (verified)
/// public prekey bundle.
pub fn initiate(
    alice_identity: &StaticSecret,
    bundle: &PrekeyBundlePublic,
) -> Result<PqxdhInitiatorResult> {
    let ephemeral = random_secret()?;
    let ephemeral_public = PublicKey::from(&ephemeral);

    // DH1 = DH(IK_A, SPK_B); DH2 = DH(EK_A, IK_B); DH3 = DH(EK_A, SPK_B)
    let dh1 = alice_identity
        .diffie_hellman(&bundle.signed_prekey)
        .to_bytes();
    let dh2 = ephemeral.diffie_hellman(&bundle.identity).to_bytes();
    let dh3 = ephemeral.diffie_hellman(&bundle.signed_prekey).to_bytes();
    // DH4 = DH(EK_A, OPK_B) if a one-time prekey is present.
    let dh4 = bundle
        .one_time_prekey
        .as_ref()
        .map(|opk| ephemeral.diffie_hellman(opk).to_bytes());

    // KEM: encapsulate to Bob's ML-KEM prekey.
    let (kem_ss, kem_ct) = kem_encapsulate(&bundle.kem_public);

    let shared_secret = derive_sk(&dh1, &dh2, &dh3, dh4.as_ref(), kem_ss.as_bytes())?;

    Ok(PqxdhInitiatorResult {
        shared_secret,
        initial_message: InitialMessage {
            identity: PublicKey::from(alice_identity),
            ephemeral: ephemeral_public,
            kem_ciphertext: kem_ct,
            used_one_time_prekey: dh4.is_some(),
        },
        bob_ratchet_public: bundle.signed_prekey,
    })
}

/// Run the responder (Bob) side. Reproduces the shared secret from
/// Bob's private bundle + Alice's initial message. Returns `sk` and the
/// ratchet secret (Bob's signed-prekey secret) to feed to
/// `DoubleRatchet::init_bob`.
pub fn respond(
    bundle: &PrekeyBundleSecret,
    initial: &InitialMessage,
) -> Result<([u8; 32], StaticSecret)> {
    // Mirror Alice's DHs with the private key of each pair swapped in.
    let dh1 = bundle
        .signed_prekey
        .diffie_hellman(&initial.identity)
        .to_bytes();
    let dh2 = bundle
        .identity
        .diffie_hellman(&initial.ephemeral)
        .to_bytes();
    let dh3 = bundle
        .signed_prekey
        .diffie_hellman(&initial.ephemeral)
        .to_bytes();
    let dh4 = if initial.used_one_time_prekey {
        let opk = bundle
            .one_time_prekey
            .as_ref()
            .ok_or_else(|| anyhow!("initiator used a one-time prekey we don't have"))?;
        Some(opk.diffie_hellman(&initial.ephemeral).to_bytes())
    } else {
        None
    };

    let kem_ss = kem_decapsulate(&initial.kem_ciphertext, &bundle.kem_secret);

    let shared_secret = derive_sk(&dh1, &dh2, &dh3, dh4.as_ref(), kem_ss.as_bytes())?;
    // Clone the signed-prekey secret for the ratchet init. (StaticSecret
    // is Clone; the original stays in the bundle for any concurrent
    // handshakes still in flight, though production should rotate it.)
    Ok((shared_secret, bundle.signed_prekey.clone()))
}

/// SK = HKDF-SHA256(ikm = DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ KEM_ss).
fn derive_sk(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
    kem_ss: &[u8],
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 * 4 + kem_ss.len());
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d4) = dh4 {
        ikm.extend_from_slice(d4);
    }
    ikm.extend_from_slice(kem_ss);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(PQXDH_KDF_INFO, &mut sk)
        .map_err(|e| anyhow!("PQXDH KDF expand: {e}"))?;
    ikm.zeroize();
    Ok(sk)
}

fn random_secret() -> Result<StaticSecret> {
    Ok(StaticSecret::from(secure_rng::random::array::<32>()?))
}

/// Generate a bundle secret together with its KEM public (which the KEM
/// secret can't reproduce, so it must be retained separately).
pub fn generate_bundle() -> Result<(PrekeyBundleSecret, KemPublicKey)> {
    let (kem_public, kem_secret) = kem_keypair();
    Ok((
        PrekeyBundleSecret {
            identity: random_secret()?,
            signed_prekey: random_secret()?,
            one_time_prekey: Some(random_secret()?),
            kem_secret,
        },
        kem_public,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::double_ratchet::DoubleRatchet;

    #[test]
    fn initiator_and_responder_agree_on_sk() {
        let (bob_secret, kem_pub) = generate_bundle().unwrap();
        let bob_public = bob_secret.public_with_kem(kem_pub);

        let alice_identity = random_secret().unwrap();
        let init = initiate(&alice_identity, &bob_public).unwrap();
        let (bob_sk, _bob_ratchet_secret) = respond(&bob_secret, &init.initial_message).unwrap();

        assert_eq!(
            init.shared_secret, bob_sk,
            "initiator and responder must derive the same PQXDH secret",
        );
    }

    #[test]
    fn agreement_without_one_time_prekey() {
        // Bundle with the one-time prekey stripped (exhausted).
        let (mut bob_secret, kem_pub) = generate_bundle().unwrap();
        bob_secret.one_time_prekey = None;
        let mut bob_public = bob_secret.public_with_kem(kem_pub);
        bob_public.one_time_prekey = None;

        let alice_identity = random_secret().unwrap();
        let init = initiate(&alice_identity, &bob_public).unwrap();
        assert!(!init.initial_message.used_one_time_prekey);
        let (bob_sk, _) = respond(&bob_secret, &init.initial_message).unwrap();
        assert_eq!(init.shared_secret, bob_sk);
    }

    #[test]
    fn pqxdh_seeds_a_working_ratchet() {
        // End-to-end: PQXDH → ratchet → exchange a message both ways.
        let (bob_secret, kem_pub) = generate_bundle().unwrap();
        let bob_public = bob_secret.public_with_kem(kem_pub);
        let alice_identity = random_secret().unwrap();

        let init = initiate(&alice_identity, &bob_public).unwrap();
        let (bob_sk, bob_ratchet_secret) = respond(&bob_secret, &init.initial_message).unwrap();

        let mut alice =
            DoubleRatchet::init_alice(init.shared_secret, init.bob_ratchet_public).unwrap();
        let mut bob = DoubleRatchet::init_bob(bob_sk, bob_ratchet_secret);

        let (h, c) = alice
            .encrypt(b"first post-quantum deniable message", b"cid")
            .unwrap();
        assert_eq!(
            bob.decrypt(&h, &c, b"cid").unwrap(),
            b"first post-quantum deniable message",
        );
        let (h2, c2) = bob.encrypt(b"reply", b"cid").unwrap();
        assert_eq!(alice.decrypt(&h2, &c2, b"cid").unwrap(), b"reply");
    }

    #[test]
    fn wrong_responder_key_yields_different_sk() {
        let (bob_secret, kem_pub) = generate_bundle().unwrap();
        let bob_public = bob_secret.public_with_kem(kem_pub);
        let alice_identity = random_secret().unwrap();
        let init = initiate(&alice_identity, &bob_public).unwrap();

        // A different Bob bundle can't reproduce the secret.
        let (other_bob, _) = generate_bundle().unwrap();
        let result = respond(&other_bob, &init.initial_message);
        // Decapsulation with the wrong KEM secret still yields *a*
        // secret (ML-KEM is designed not to fail), but it differs, so
        // the derived SK differs.
        if let Ok((other_sk, _)) = result {
            assert_ne!(init.shared_secret, other_sk);
        }
    }
}
