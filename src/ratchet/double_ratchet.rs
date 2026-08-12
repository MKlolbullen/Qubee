//! Double Ratchet — the core of Qubee's forward-secret, deniable 1:1
//! messaging.
//!
//! This is a faithful implementation of the Signal Double Ratchet
//! algorithm (Perrin & Marlinspike) adapted to Qubee's primitives:
//!
//! * **DH ratchet:** X25519.
//! * **Root KDF:** HKDF-SHA256 (`salt = root key`, `ikm = DH output`).
//! * **Chain KDF:** BLAKE3 keyed hash (`key = chain key`, distinct
//!   one-byte domain tags for the message key vs. the next chain key).
//! * **AEAD:** ChaCha20-Poly1305, key + nonce derived from the message
//!   key via HKDF-SHA256. The message header is bound as associated
//!   data.
//!
//! **Forward secrecy + post-compromise security:** each message uses a
//! fresh message key derived by advancing a chain key one step; the
//! chain key is overwritten, so a compromise reveals nothing about
//! already-sent messages. Every round-trip performs a DH ratchet step
//! that folds fresh entropy into the root key, so a compromise heals
//! after one round-trip.
//!
//! **Deniability:** messages are authenticated *only* by the
//! Poly1305 tag under the per-message key. Both the sender and the
//! receiver derive that key, so a transcript proves nothing about
//! authorship to a third party — the opposite of the previous
//! sign-every-message design. There are no per-message signatures
//! here.
//!
//! The post-quantum initial key agreement (PQXDH — X25519 DHs +
//! ML-KEM-768 encapsulation) lives alongside this module and produces
//! the 32-byte shared secret (`sk`) that seeds [`DoubleRatchet::init_alice`]
//! / [`init_bob`]; the ongoing ratchet here is classical X25519 (a
//! periodic KEM re-injection to make the *ongoing* ratchet post-quantum
//! is a documented follow-on stage).

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::security::secure_rng;

/// Max message keys we will skip within a single receiving chain before
/// declaring the gap hostile. Bounds the work + memory an attacker (or a
/// very lossy link) can force by sending a message with a large index.
pub const MAX_SKIP: u32 = 1000;

/// Hard cap on retained skipped message keys across all chains, so a
/// stream of new-ratchet-key messages each skipping ~MAX_SKIP can't grow
/// the map without bound.
const MAX_SKIPPED_STORE: usize = 2000;

const ROOT_KDF_INFO: &[u8] = b"qubee_ratchet_root_v1";
const MSG_KDF_INFO: &[u8] = b"qubee_ratchet_message_v1";
const CHAIN_MK_TAG: &[u8] = &[0x01];
const CHAIN_CK_TAG: &[u8] = &[0x02];

/// Per-message header sent in the clear alongside the ciphertext. It is
/// also bound as AEAD associated data, so tampering with any field
/// fails decryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's current ratchet public key.
    pub dh: [u8; 32],
    /// Number of messages in the previous sending chain (lets the
    /// receiver skip the tail of the old chain on a ratchet step).
    pub pn: u32,
    /// Message number within the current sending chain.
    pub n: u32,
}

impl MessageHeader {
    /// Canonical 40-byte encoding used as AEAD associated data.
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 40 {
            return Err(anyhow!("ratchet header must be 40 bytes"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        let pn = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let n = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        Ok(MessageHeader { dh, pn, n })
    }
}

/// A single Double Ratchet session (one peer, one device pair).
///
/// Not `Clone` on purpose — a ratchet state must never be duplicated
/// (a fork would reuse message keys). Persistence should serialise +
/// re-load, not clone.
pub struct DoubleRatchet {
    /// Our current sending ratchet secret + its public.
    dhs_secret: StaticSecret,
    dhs_public: PublicKey,
    /// Their current ratchet public (None until the first inbound on
    /// the Bob-initialised side).
    dhr: Option<PublicKey>,
    /// Root key.
    rk: [u8; 32],
    /// Sending chain key (None on Bob's side until his first send after
    /// receiving).
    cks: Option<[u8; 32]>,
    /// Receiving chain key.
    ckr: Option<[u8; 32]>,
    /// Message number, sending chain.
    ns: u32,
    /// Message number, receiving chain.
    nr: u32,
    /// Length of the previous sending chain.
    pn: u32,
    /// Message keys skipped (received out of order): (their DH pub, n) -> mk.
    /// FIFO-bounded by `MAX_SKIPPED_STORE`.
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
    /// Insertion order for FIFO eviction of `skipped`.
    skipped_order: Vec<([u8; 32], u32)>,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        // StaticSecret zeroizes itself. Zeroize the raw key material we
        // hold directly.
        self.rk.zeroize();
        if let Some(ck) = self.cks.as_mut() {
            ck.zeroize();
        }
        if let Some(ck) = self.ckr.as_mut() {
            ck.zeroize();
        }
        for mk in self.skipped.values_mut() {
            mk.zeroize();
        }
    }
}

/// Serialisable shadow of [`DoubleRatchet`]. X25519 `StaticSecret` and
/// the raw chain keys don't implement serde, so persistence round-trips
/// through this byte-array mirror. `dhs_public` is omitted — it is
/// recomputed from `dhs_secret` on load. Holds live message-key material
/// (chain keys + skipped keys), so its bytes must only ever live inside
/// the encrypted keystore, never on the wire.
#[derive(Serialize, Deserialize)]
struct WireRatchetState {
    dhs_secret: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    /// `(their_dh, n) -> message_key`, flattened in `skipped_order` order
    /// so the FIFO eviction queue is preserved exactly across reloads.
    skipped: Vec<([u8; 32], u32, [u8; 32])>,
}

impl DoubleRatchet {
    /// Serialise the full ratchet state for encrypted-at-rest
    /// persistence. The output contains live key material and must be
    /// stored only in the [`crate::storage::secure_keystore::SecureKeyStore`].
    pub fn serialize_state(&self) -> Result<Vec<u8>> {
        // Preserve the exact FIFO order of `skipped_order` so eviction
        // behaviour is identical after a reload.
        let skipped = self
            .skipped_order
            .iter()
            .filter_map(|k| self.skipped.get(k).map(|mk| (k.0, k.1, *mk)))
            .collect();
        let wire = WireRatchetState {
            dhs_secret: self.dhs_secret.to_bytes(),
            dhr: self.dhr.map(|p| *p.as_bytes()),
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped,
        };
        bincode::serialize(&wire).map_err(|e| anyhow!("serialize ratchet state: {e}"))
    }

    /// Reconstruct a ratchet from [`serialize_state`] output. The
    /// resulting session continues exactly where the serialised one left
    /// off — message numbers, chain keys, and skipped keys are restored,
    /// so no message key is ever reused.
    pub fn deserialize_state(bytes: &[u8]) -> Result<Self> {
        let wire: WireRatchetState =
            bincode::deserialize(bytes).map_err(|e| anyhow!("deserialize ratchet state: {e}"))?;
        let dhs_secret = StaticSecret::from(wire.dhs_secret);
        let dhs_public = PublicKey::from(&dhs_secret);
        let mut skipped = HashMap::with_capacity(wire.skipped.len());
        let mut skipped_order = Vec::with_capacity(wire.skipped.len());
        for (dh, n, mk) in wire.skipped {
            let key = (dh, n);
            if skipped.insert(key, mk).is_none() {
                skipped_order.push(key);
            }
        }
        Ok(DoubleRatchet {
            dhs_secret,
            dhs_public,
            dhr: wire.dhr.map(PublicKey::from),
            rk: wire.rk,
            cks: wire.cks,
            ckr: wire.ckr,
            ns: wire.ns,
            nr: wire.nr,
            pn: wire.pn,
            skipped,
            skipped_order,
        })
    }

    /// Initialise the *initiator* (Alice) side after the PQXDH shared
    /// secret `sk` has been established. `bob_dh_public` is Bob's
    /// signed-prekey ratchet public.
    pub fn init_alice(sk: [u8; 32], bob_dh_public: PublicKey) -> Result<Self> {
        let dhs_secret = random_secret()?;
        let dhs_public = PublicKey::from(&dhs_secret);
        let dh_out = dhs_secret.diffie_hellman(&bob_dh_public).to_bytes();
        let (rk, cks) = kdf_rk(&sk, &dh_out)?;
        Ok(DoubleRatchet {
            dhs_secret,
            dhs_public,
            dhr: Some(bob_dh_public),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            skipped_order: Vec::new(),
        })
    }

    /// Initialise the *responder* (Bob) side. `bob_dh_secret` is the
    /// private half of the ratchet key whose public Alice used in
    /// `init_alice`. Bob has no sending chain until he receives Alice's
    /// first message and performs his first DH ratchet step.
    pub fn init_bob(sk: [u8; 32], bob_dh_secret: StaticSecret) -> Self {
        let dhs_public = PublicKey::from(&bob_dh_secret);
        DoubleRatchet {
            dhs_secret: bob_dh_secret,
            dhs_public,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            skipped_order: Vec::new(),
        }
    }

    /// Our current ratchet public key (Bob publishes this as his signed
    /// prekey; used by tests + the session-setup layer).
    pub fn dh_public(&self) -> PublicKey {
        self.dhs_public
    }

    /// Encrypt `plaintext`, binding `associated_data` (e.g. a
    /// conversation id) in addition to the header. Returns the header
    /// to send in the clear and the ciphertext.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>)> {
        let cks = self
            .cks
            .as_mut()
            .ok_or_else(|| anyhow!("no sending chain yet (Bob must receive before sending)"))?;
        let (next_ck, mk) = kdf_ck(cks);
        *cks = next_ck;

        let header = MessageHeader {
            dh: *self.dhs_public.as_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let aad = concat_aad(associated_data, &header);
        let ciphertext = aead_encrypt(&mk, plaintext, &aad)?;
        Ok((header, ciphertext))
    }

    /// Decrypt a message given its header + ciphertext + the same
    /// `associated_data` the sender used. Handles out-of-order delivery
    /// (via skipped-key storage) and DH ratchet steps.
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Ratchet on a throwaway copy and commit it back only once the
        // AEAD verifies. Without this, the receive-side mutations
        // (DH-ratchet step, chain-key advance, nr/pn bumps) happen
        // *before* authentication — so a spoofed or corrupt frame would
        // poison the live session. Persisting only on success (the
        // session/keystore layer) contains that today, but as soon as a
        // caller holds the ratchet in memory (the obvious per-message
        // cache), one forged packet would brick the session. Staging
        // makes the atomicity structural rather than caller-dependent.
        //
        // The staged copy holds a second transient copy of the chain
        // secrets; both it and the replaced `self` zeroise on drop, and
        // no message key is ever *reused* (the point of `!Clone`), so
        // this doesn't reopen the fork hazard the type guards against.
        let mut staged = self.snapshot();
        let plaintext = staged.decrypt_in_place(header, ciphertext, associated_data)?;
        *self = staged;
        Ok(plaintext)
    }

    /// A private, transient duplicate of the ratchet for staged decrypt.
    /// **Not** the `Clone` trait — duplicating a ratchet into two live
    /// sessions would reuse message keys, which is exactly what the
    /// missing `Clone` impl prevents. This copy is committed back or
    /// dropped within a single `decrypt` call.
    fn snapshot(&self) -> Self {
        DoubleRatchet {
            dhs_secret: self.dhs_secret.clone(),
            dhs_public: self.dhs_public,
            dhr: self.dhr,
            rk: self.rk,
            cks: self.cks,
            ckr: self.ckr,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
            skipped_order: self.skipped_order.clone(),
        }
    }

    /// The mutating receive path, run on the staged copy.
    fn decrypt_in_place(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. A skipped key for exactly this (dh, n)? (single-use)
        if let Some(pt) = self.try_skipped(header, ciphertext, associated_data)? {
            return Ok(pt);
        }

        let their_dh = PublicKey::from(header.dh);
        let is_new_ratchet = match &self.dhr {
            Some(cur) => cur.as_bytes() != their_dh.as_bytes(),
            None => true,
        };

        // 2. Reject replays of already-consumed current-chain messages
        //    up front: a frame on the current receive chain (same DH)
        //    with `n < nr` and no matching skipped key is a message we
        //    already delivered. Erroring here — before advancing the
        //    chain or spending ~`MAX_SKIP` BLAKE3 iterations — stops a
        //    replayed frame from burning a message key and doubles as a
        //    cheap DoS guard.
        if !is_new_ratchet && header.n < self.nr {
            return Err(anyhow!(
                "replayed or already-consumed message (n < nr, no skipped key)"
            ));
        }

        // 3. New ratchet public key ⇒ skip the rest of the old recv
        //    chain, then perform a DH ratchet step.
        if is_new_ratchet {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(&their_dh)?;
        }

        // 4. Skip up to this message in the current recv chain.
        self.skip_message_keys(header.n)?;

        // 5. Derive the message key and decrypt.
        let ckr = self
            .ckr
            .as_mut()
            .ok_or_else(|| anyhow!("no receiving chain"))?;
        let (next_ck, mk) = kdf_ck(ckr);
        *ckr = next_ck;
        self.nr += 1;

        let aad = concat_aad(associated_data, header);
        aead_decrypt(&mk, ciphertext, &aad)
            .ok_or_else(|| anyhow!("ratchet decrypt failed (auth/tamper/replay)"))
    }

    fn try_skipped(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let key = (header.dh, header.n);
        if let Some(mk) = self.skipped.get(&key).copied() {
            let aad = concat_aad(associated_data, header);
            match aead_decrypt(&mk, ciphertext, &aad) {
                Some(pt) => {
                    // Consume the skipped key (single use — replays of
                    // this exact message now fail).
                    if let Some(mut removed) = self.skipped.remove(&key) {
                        removed.zeroize();
                    }
                    self.skipped_order.retain(|k| k != &key);
                    Ok(Some(pt))
                }
                None => Err(anyhow!("skipped-key decrypt failed (tamper)")),
            }
        } else {
            Ok(None)
        }
    }

    /// Advance the receiving chain up to `until`, stashing each skipped
    /// message key for later out-of-order delivery. Errors if the gap
    /// exceeds `MAX_SKIP`.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.ckr.is_none() {
            return Ok(());
        }
        if until > self.nr && until - self.nr > MAX_SKIP {
            return Err(anyhow!(
                "too many skipped messages ({} > MAX_SKIP {})",
                until - self.nr,
                MAX_SKIP
            ));
        }
        let dhr_bytes = match &self.dhr {
            Some(pk) => *pk.as_bytes(),
            None => return Ok(()),
        };
        while self.nr < until {
            let ckr = self.ckr.as_mut().expect("checked is_some");
            let (next_ck, mk) = kdf_ck(ckr);
            *ckr = next_ck;
            let key = (dhr_bytes, self.nr);
            self.insert_skipped(key, mk);
            self.nr += 1;
        }
        Ok(())
    }

    fn insert_skipped(&mut self, key: ([u8; 32], u32), mk: [u8; 32]) {
        if self.skipped.insert(key, mk).is_none() {
            self.skipped_order.push(key);
        }
        // FIFO-evict oldest if over the hard cap.
        while self.skipped_order.len() > MAX_SKIPPED_STORE {
            let oldest = self.skipped_order.remove(0);
            if let Some(mut old_mk) = self.skipped.remove(&oldest) {
                old_mk.zeroize();
            }
        }
    }

    /// Perform a DH ratchet step against `their_dh`: derive a new
    /// receiving chain from the old sending key, generate a fresh
    /// sending ratchet key, and derive a new sending chain.
    fn dh_ratchet(&mut self, their_dh: &PublicKey) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*their_dh);

        let dh1 = self.dhs_secret.diffie_hellman(their_dh).to_bytes();
        let (rk1, ckr) = kdf_rk(&self.rk, &dh1)?;
        self.rk = rk1;
        self.ckr = Some(ckr);

        // Fresh sending ratchet keypair, then the sending chain.
        let new_secret = random_secret()?;
        let new_public = PublicKey::from(&new_secret);
        let dh2 = new_secret.diffie_hellman(their_dh).to_bytes();
        let (rk2, cks) = kdf_rk(&self.rk, &dh2)?;
        self.rk = rk2;
        self.cks = Some(cks);
        self.dhs_secret = new_secret;
        self.dhs_public = new_public;
        Ok(())
    }
}

// --- KDFs -------------------------------------------------------------

/// Root KDF: `HKDF-SHA256(salt = rk, ikm = dh_out)` → (new root key,
/// new chain key).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(ROOT_KDF_INFO, &mut okm)
        .map_err(|e| anyhow!("root KDF expand: {e}"))?;
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((new_rk, ck))
}

/// Chain KDF: BLAKE3 keyed hash under the chain key with distinct
/// one-byte domain tags → (next chain key, message key).
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = *blake3::keyed_hash(ck, CHAIN_MK_TAG).as_bytes();
    let next_ck = *blake3::keyed_hash(ck, CHAIN_CK_TAG).as_bytes();
    (next_ck, mk)
}

/// Derive the AEAD key (32) + nonce (12) from a message key.
fn derive_message_aead(mk: &[u8; 32]) -> Result<([u8; 32], [u8; 12])> {
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut okm = [0u8; 44];
    hk.expand(MSG_KDF_INFO, &mut okm)
        .map_err(|e| anyhow!("message KDF expand: {e}"))?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((key, nonce))
}

// --- AEAD -------------------------------------------------------------

fn aead_encrypt(mk: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let (mut key, nonce) = derive_message_aead(mk)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    key.zeroize();
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("ratchet AEAD encrypt: {e:?}"))
}

/// Returns `None` on any authentication failure (wrong key, tamper,
/// replay of a consumed key).
fn aead_decrypt(mk: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let (mut key, nonce) = derive_message_aead(mk).ok()?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    key.zeroize();
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

fn concat_aad(external: &[u8], header: &MessageHeader) -> Vec<u8> {
    let hb = header.to_bytes();
    let mut out = Vec::with_capacity(external.len() + hb.len());
    out.extend_from_slice(external);
    out.extend_from_slice(&hb);
    out
}

fn random_secret() -> Result<StaticSecret> {
    // Use the project CSPRNG to fill 32 bytes; x25519-dalek clamps on
    // use, so raw random bytes are the correct input.
    let bytes = secure_rng::random::array::<32>()?;
    Ok(StaticSecret::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Establish a fresh Alice/Bob pair sharing a random `sk` and Bob's
    /// ratchet keypair, exactly as the PQXDH layer will drive it.
    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let sk = secure_rng::random::array::<32>().unwrap();
        let bob_secret = random_secret().unwrap();
        let bob_public = PublicKey::from(&bob_secret);
        let alice = DoubleRatchet::init_alice(sk, bob_public).unwrap();
        let bob = DoubleRatchet::init_bob(sk, bob_secret);
        (alice, bob)
    }

    const AD: &[u8] = b"conversation-id";

    #[test]
    fn full_duplex_ping_pong() {
        let (mut alice, mut bob) = pair();

        // Alice -> Bob (Alice has the first sending chain).
        let (h1, c1) = alice.encrypt(b"hello bob", AD).unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, AD).unwrap(), b"hello bob");

        // Bob -> Alice (Bob now has a sending chain after his ratchet step).
        let (h2, c2) = bob.encrypt(b"hi alice", AD).unwrap();
        assert_eq!(alice.decrypt(&h2, &c2, AD).unwrap(), b"hi alice");

        // Several more round-trips, each performs a DH ratchet step.
        for i in 0..5u32 {
            let m = format!("a{i}");
            let (h, c) = alice.encrypt(m.as_bytes(), AD).unwrap();
            assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), m.as_bytes());
            let r = format!("b{i}");
            let (h, c) = bob.encrypt(r.as_bytes(), AD).unwrap();
            assert_eq!(alice.decrypt(&h, &c, AD).unwrap(), r.as_bytes());
        }
    }

    #[test]
    fn failed_decrypt_does_not_poison_the_session() {
        let (mut alice, mut bob) = pair();
        let (h1, c1) = alice.encrypt(b"first", AD).unwrap();

        // A tampered ciphertext for the very first message must fail
        // *and* leave Bob's ratchet exactly as it was — the staged copy
        // is discarded on AEAD failure, no chain advance.
        let mut tampered = c1.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(bob.decrypt(&h1, &tampered, AD).is_err());

        // The genuine first message still decrypts (state wasn't
        // advanced by the failed attempt). Pre-staging, the DH-ratchet
        // step + nr bump from the failed frame would have desynced Bob.
        assert_eq!(bob.decrypt(&h1, &c1, AD).unwrap(), b"first");

        // And the conversation continues normally both directions.
        let (h2, c2) = alice.encrypt(b"second", AD).unwrap();
        assert_eq!(bob.decrypt(&h2, &c2, AD).unwrap(), b"second");
        let (h3, c3) = bob.encrypt(b"reply", AD).unwrap();
        assert_eq!(alice.decrypt(&h3, &c3, AD).unwrap(), b"reply");
    }

    #[test]
    fn replayed_frame_is_rejected_without_advancing() {
        let (mut alice, mut bob) = pair();
        let (h1, c1) = alice.encrypt(b"m1", AD).unwrap();
        let (h2, c2) = alice.encrypt(b"m2", AD).unwrap();

        assert_eq!(bob.decrypt(&h1, &c1, AD).unwrap(), b"m1");
        assert_eq!(bob.decrypt(&h2, &c2, AD).unwrap(), b"m2");

        // Replaying m1 (n=0 < nr=2, no skipped key) is rejected up front,
        // before any chain work — its message key was consumed on first
        // delivery and is not retained.
        assert!(bob.decrypt(&h1, &c1, AD).is_err());
        assert!(bob.decrypt(&h2, &c2, AD).is_err());

        // A fresh in-order message still decrypts, proving the replays
        // didn't move nr or the chain key.
        let (h3, c3) = alice.encrypt(b"m3", AD).unwrap();
        assert_eq!(bob.decrypt(&h3, &c3, AD).unwrap(), b"m3");
    }

    #[test]
    fn out_of_order_within_a_chain() {
        let (mut alice, mut bob) = pair();
        let (h1, c1) = alice.encrypt(b"m1", AD).unwrap();
        let (h2, c2) = alice.encrypt(b"m2", AD).unwrap();
        let (h3, c3) = alice.encrypt(b"m3", AD).unwrap();

        // Bob receives out of order: 3, 1, 2.
        assert_eq!(bob.decrypt(&h3, &c3, AD).unwrap(), b"m3");
        assert_eq!(bob.decrypt(&h1, &c1, AD).unwrap(), b"m1");
        assert_eq!(bob.decrypt(&h2, &c2, AD).unwrap(), b"m2");
    }

    #[test]
    fn out_of_order_across_ratchet_steps() {
        let (mut alice, mut bob) = pair();

        // Round 1
        let (ha, ca) = alice.encrypt(b"a-1", AD).unwrap();
        bob.decrypt(&ha, &ca, AD).unwrap();
        let (hb, cb) = bob.encrypt(b"b-1", AD).unwrap();
        alice.decrypt(&hb, &cb, AD).unwrap();

        // Alice sends two more, Bob a straggler from before; deliver the
        // straggler after the new-chain message.
        let (ha2, ca2) = alice.encrypt(b"a-2", AD).unwrap();
        let (ha3, ca3) = alice.encrypt(b"a-3", AD).unwrap();
        assert_eq!(bob.decrypt(&ha3, &ca3, AD).unwrap(), b"a-3");
        assert_eq!(bob.decrypt(&ha2, &ca2, AD).unwrap(), b"a-2");
    }

    #[test]
    fn tampering_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (h, mut c) = alice.encrypt(b"secret", AD).unwrap();
        c[0] ^= 0x01;
        assert!(bob.decrypt(&h, &c, AD).is_err(), "AEAD must reject tamper");

        // A tampered header field is also rejected (header is AAD).
        let (h2, c2) = alice.encrypt(b"secret2", AD).unwrap();
        let mut bad = h2.clone();
        bad.n ^= 0x01;
        assert!(
            bob.decrypt(&bad, &c2, AD).is_err(),
            "header is authenticated"
        );
    }

    #[test]
    fn wrong_associated_data_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (h, c) = alice.encrypt(b"secret", AD).unwrap();
        assert!(
            bob.decrypt(&h, &c, b"different-conversation").is_err(),
            "external AD is bound into the AEAD",
        );
    }

    #[test]
    fn replay_of_a_consumed_message_fails() {
        let (mut alice, mut bob) = pair();
        let (h, c) = alice.encrypt(b"once", AD).unwrap();
        assert_eq!(bob.decrypt(&h, &c, AD).unwrap(), b"once");
        // The receiving chain has advanced past this key; replaying the
        // same frame no longer matches a live or skipped key.
        assert!(bob.decrypt(&h, &c, AD).is_err(), "replay must fail");
    }

    #[test]
    fn exceeding_max_skip_is_rejected() {
        let (mut alice, mut bob) = pair();
        // Alice sends MAX_SKIP + 2 messages; Bob only ever sees the last.
        let mut last = None;
        for i in 0..(MAX_SKIP + 2) {
            let (h, c) = alice.encrypt(format!("m{i}").as_bytes(), AD).unwrap();
            if i == MAX_SKIP + 1 {
                last = Some((h, c));
            }
        }
        let (h, c) = last.unwrap();
        assert!(
            bob.decrypt(&h, &c, AD).is_err(),
            "skipping more than MAX_SKIP must be refused",
        );
    }

    #[test]
    fn header_round_trips() {
        let h = MessageHeader {
            dh: [7u8; 32],
            pn: 42,
            n: 9,
        };
        let back = MessageHeader::from_bytes(&h.to_bytes()).unwrap();
        assert_eq!(h, back);
        assert!(MessageHeader::from_bytes(&[0u8; 39]).is_err());
    }

    #[test]
    fn serialized_ratchet_resumes_mid_conversation() {
        let (mut alice, mut bob) = pair();

        // Exchange a few messages, then persist both sides mid-stream.
        let (h1, c1) = alice.encrypt(b"a-1", AD).unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, AD).unwrap(), b"a-1");
        let (h2, c2) = bob.encrypt(b"b-1", AD).unwrap();
        assert_eq!(alice.decrypt(&h2, &c2, AD).unwrap(), b"b-1");

        let alice_bytes = alice.serialize_state().unwrap();
        let bob_bytes = bob.serialize_state().unwrap();
        drop(alice);
        drop(bob);

        // Reload from disk-shaped bytes and keep going — no key reuse,
        // conversation continues transparently across the restart.
        let mut alice = DoubleRatchet::deserialize_state(&alice_bytes).unwrap();
        let mut bob = DoubleRatchet::deserialize_state(&bob_bytes).unwrap();
        let (h3, c3) = alice.encrypt(b"a-2 after reload", AD).unwrap();
        assert_eq!(bob.decrypt(&h3, &c3, AD).unwrap(), b"a-2 after reload");
        let (h4, c4) = bob.encrypt(b"b-2 after reload", AD).unwrap();
        assert_eq!(alice.decrypt(&h4, &c4, AD).unwrap(), b"b-2 after reload");
    }

    #[test]
    fn serialized_ratchet_preserves_pending_skipped_keys() {
        let (mut alice, mut bob) = pair();
        // Alice sends three; Bob decrypts only the third, stashing skipped
        // keys for m1 + m2. Persist Bob mid-gap.
        let (h1, c1) = alice.encrypt(b"m1", AD).unwrap();
        let (h2, c2) = alice.encrypt(b"m2", AD).unwrap();
        let (h3, c3) = alice.encrypt(b"m3", AD).unwrap();
        assert_eq!(bob.decrypt(&h3, &c3, AD).unwrap(), b"m3");

        let bob_bytes = bob.serialize_state().unwrap();
        drop(bob);
        let mut bob = DoubleRatchet::deserialize_state(&bob_bytes).unwrap();

        // The straggler keys survived the round-trip: out-of-order m1 + m2
        // still decrypt, and each remains single-use (replay fails).
        assert_eq!(bob.decrypt(&h1, &c1, AD).unwrap(), b"m1");
        assert_eq!(bob.decrypt(&h2, &c2, AD).unwrap(), b"m2");
        assert!(
            bob.decrypt(&h1, &c1, AD).is_err(),
            "skipped key is single-use"
        );
    }

    #[test]
    fn independent_sessions_do_not_interoperate() {
        // Two unrelated pairs (different sk) must not cross-decrypt —
        // a sanity check that the shared secret actually gates the
        // session.
        let (mut alice1, _bob1) = pair();
        let (_alice2, mut bob2) = pair();
        let (h, c) = alice1.encrypt(b"hi", AD).unwrap();
        assert!(bob2.decrypt(&h, &c, AD).is_err());
    }
}
