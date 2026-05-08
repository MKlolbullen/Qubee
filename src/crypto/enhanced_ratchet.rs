//! Symmetric forward-secret ratchet seeded from a hybrid (classical
//! + post-quantum) shared secret.
//!
//! # Threat model
//!
//! * **Forward secrecy**: each direction maintains its own chain key
//!   that's advanced via HKDF-SHA256 on every send. Recovering the
//!   chain at counter `n` from an attacker-known chain at counter
//!   `n+1` requires breaking SHA256 — i.e. compromising a peer
//!   *after* a message was delivered doesn't reveal earlier
//!   message keys.
//! * **Confidentiality and integrity** are provided by ChaCha20-
//!   Poly1305 over `(plaintext, aad)`. Each message uses a fresh
//!   12-byte random nonce that's embedded in the wire frame.
//! * **Out-of-order delivery within a fixed skip window
//!   ([`MAX_SKIP`])**. Messages whose counter jumps further ahead
//!   than that are refused so an attacker can't drive arbitrary
//!   work into the recipient.
//!
//! # What this isn't
//!
//! Not a full Signal Double Ratchet. There's no per-message DH
//! step, so the post-compromise security guarantee is weaker than
//! Signal's: an attacker who reads a peer's state can decrypt
//! every subsequent message until a fresh handshake replaces the
//! ratchet. The chain-only design is appropriate for short-lived
//! sessions or where re-handshaking is cheap; long-running channels
//! need to layer a DH ratchet on top.
//!
//! Skipped-message keys *are* stashed: when a message arrives whose
//! counter is ahead of the local recv counter (but inside [`MAX_SKIP`]),
//! the intermediate per-counter keys are derived and stored in a
//! bounded `HashMap<u32, Zeroizing<[u8; KEY_LEN]>>` so a later out-of-
//! order arrival of those counters still decrypts. The stash is
//! capped at [`MAX_SKIPPED_STASH`] entries; once full, the oldest
//! counter is evicted and any later arrival of *that* counter is
//! refused. This matches Signal-style replay-tolerance within the
//! skip window without giving an attacker an unbounded memory
//! amplifier.
//!
//! # Wire format
//!
//! ```text
//! +-----------+-------------+----------------------------------------+
//! | counter   | nonce (12B) | ChaCha20-Poly1305 ciphertext + tag    |
//! | u32 BE    |             | (aad bound externally, not on wire)   |
//! +-----------+-------------+----------------------------------------+
//! ```
//!
//! AAD is bound by the caller — typically session id, sender
//! identity, or message metadata that must stay tamper-evident
//! without being encrypted.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

use crate::security::secure_rng;

/// Cap on how far ahead a single received message may jump the
/// recv chain. 1024 lets a peer absorb a moderate burst of out-of-
/// order delivery (e.g. a sender unblocking after a network stall)
/// while keeping the worst-case work per packet bounded.
pub const MAX_SKIP: u32 = 1024;

/// Cap on how many message keys may be held simultaneously in the
/// skipped-key stash. Prevents an attacker — or a series of
/// legitimate gaps that never get filled — from growing memory
/// usage without bound. When the stash is full we evict the oldest
/// counter to make room; that key is gone forever and any later
/// arrival of its message is rejected as stale.
pub const MAX_SKIPPED_STASH: usize = 4096;

/// Length of the symmetric AEAD key (and chain key).
const KEY_LEN: usize = 32;
/// Length of the AEAD nonce.
const NONCE_LEN: usize = 12;

/// HKDF info strings. Domain-separated so the same `combined_secret`
/// can't accidentally collide with another protocol that also runs
/// HKDF-SHA256 over it.
const INFO_INIT_A: &[u8] = b"qubee/ehr/v1/init/a";
const INFO_INIT_B: &[u8] = b"qubee/ehr/v1/init/b";
const INFO_CHAIN_NEXT: &[u8] = b"qubee/ehr/v1/chain/next";
const INFO_MESSAGE: &[u8] = b"qubee/ehr/v1/chain/msg";

/// Which side of the handshake this ratchet sits on. Determines
/// which derived chain serves as the send chain vs the recv
/// chain — the two peers must agree, otherwise a's send chain
/// won't line up with b's recv chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RatchetRole {
    /// The peer that sent the first handshake message. Sends on
    /// chain A, receives on chain B.
    Initiator,
    /// The peer that responded to the handshake. Sends on chain
    /// B, receives on chain A.
    Responder,
}

/// Symmetric chain key. Held in a `SecretBox` so it zeroises on
/// drop; advanced by `step` which consumes the previous key and
/// returns a freshly derived one.
struct ChainKey(SecretBox<[u8; KEY_LEN]>);

impl ChainKey {
    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Pull the next per-message key from this chain and overwrite
    /// `self` with the chained successor. Returns the key the
    /// caller should hand to ChaCha20-Poly1305.
    fn step(&mut self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let current = self.0.expose_secret();

        let mut next = [0u8; KEY_LEN];
        Hkdf::<Sha256>::from_prk(current)
            .map_err(|e| anyhow::anyhow!("hkdf prk (chain): {e}"))?
            .expand(INFO_CHAIN_NEXT, &mut next)
            .map_err(|e| anyhow::anyhow!("hkdf expand (chain): {e}"))?;

        let mut msg = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::from_prk(current)
            .map_err(|e| anyhow::anyhow!("hkdf prk (msg): {e}"))?
            .expand(INFO_MESSAGE, msg.as_mut())
            .map_err(|e| anyhow::anyhow!("hkdf expand (msg): {e}"))?;

        // Replace self with the new chain key. The previous chain
        // key bytes are zeroised when the old SecretBox is
        // dropped.
        self.0 = SecretBox::new(Box::new(next));
        Ok(msg)
    }

    /// Internal-only deep copy. Lets `decrypt` advance a working
    /// chain without committing the mutation back to `self` until
    /// AEAD has verified the message. Without this, a forged frame
    /// with a high counter would permanently corrupt the recv
    /// chain past where any legitimate message can land.
    fn duplicate(&self) -> Self {
        Self(SecretBox::new(Box::new(*self.0.expose_secret())))
    }
}

/// Hybrid forward-secret symmetric ratchet. Two chains (send +
/// recv) seeded from a single shared secret; each chain advances
/// per-message via HKDF-SHA256. See module docs for the full
/// threat model and limits.
pub struct EnhancedHybridRatchet {
    send_chain: ChainKey,
    recv_chain: ChainKey,
    send_counter: u32,
    /// Counter of the next message we expect to receive — i.e. one
    /// past the highest counter we've successfully decrypted.
    recv_next_counter: u32,
    /// Per-message keys derived for counters that arrived out of
    /// order. Each entry holds the AEAD key for the message at
    /// that counter; the entry is removed when the corresponding
    /// message finally arrives, or evicted when the stash hits
    /// [`MAX_SKIPPED_STASH`].
    skipped_message_keys: HashMap<u32, Zeroizing<[u8; KEY_LEN]>>,
}

impl EnhancedHybridRatchet {
    /// Seed a ratchet from a hybrid shared secret. The caller is
    /// expected to have already combined the classical and
    /// post-quantum components (e.g. by hashing
    /// `dh_classical || kyber_ss` together) — this constructor
    /// just splits the result into two chain keys via HKDF-SHA256.
    ///
    /// `combined_secret` must be at least 32 bytes; longer is fine
    /// (HKDF handles arbitrary-length input keying material).
    pub fn from_shared_secret(combined_secret: &[u8], role: RatchetRole) -> Result<Self> {
        if combined_secret.len() < KEY_LEN {
            return Err(anyhow::anyhow!(
                "combined_secret must be ≥ {} bytes; got {}",
                KEY_LEN,
                combined_secret.len()
            ));
        }

        let hk = Hkdf::<Sha256>::new(None, combined_secret);
        let mut chain_a = [0u8; KEY_LEN];
        let mut chain_b = [0u8; KEY_LEN];
        hk.expand(INFO_INIT_A, &mut chain_a)
            .map_err(|e| anyhow::anyhow!("hkdf expand init/a: {e}"))?;
        hk.expand(INFO_INIT_B, &mut chain_b)
            .map_err(|e| anyhow::anyhow!("hkdf expand init/b: {e}"))?;

        let (send_bytes, recv_bytes) = match role {
            RatchetRole::Initiator => (chain_a, chain_b),
            RatchetRole::Responder => (chain_b, chain_a),
        };

        let send_chain = ChainKey::from_bytes(send_bytes);
        let recv_chain = ChainKey::from_bytes(recv_bytes);

        // The plaintext copies on the stack just got moved into
        // SecretBoxes, so the SecretBoxes own the only live copies.
        // Belt-and-braces zeroise the locals anyway in case the
        // optimiser kept them around.
        let mut chain_a = chain_a;
        let mut chain_b = chain_b;
        chain_a.zeroize();
        chain_b.zeroize();

        Ok(Self {
            send_chain,
            recv_chain,
            send_counter: 0,
            recv_next_counter: 0,
            skipped_message_keys: HashMap::new(),
        })
    }

    /// Encrypt a message. Wire bytes carry the counter and nonce so
    /// the peer can identify which chain step to advance to.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let counter = self.send_counter;
        let msg_key = self.send_chain.step()?;
        let nonce_bytes = secure_rng::random::array::<NONCE_LEN>()?;

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"))?;
        // msg_key zeroises on drop here.

        self.send_counter = self
            .send_counter
            .checked_add(1)
            .context("send counter overflow — re-handshake required")?;

        let mut wire = Vec::with_capacity(4 + NONCE_LEN + ct.len());
        wire.extend_from_slice(&counter.to_be_bytes());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Decrypt a message.
    ///
    /// Three counter regimes:
    ///
    /// * `counter < recv_next_counter` — out-of-order delivery
    ///   for a message whose key we stashed earlier. We pull the
    ///   key from the stash, AEAD-decrypt, and remove the entry.
    ///   If the key isn't there it's either a replay or a delivery
    ///   that arrived after its stash entry was evicted; either
    ///   way, rejected.
    ///
    /// * `counter == recv_next_counter` — the in-order case. Step
    ///   the recv chain once, AEAD-decrypt, advance.
    ///
    /// * `counter > recv_next_counter` — out-of-order delivery
    ///   skipping ahead. Step the chain `skip + 1` times against
    ///   a working copy, AEAD-decrypt with the final key, and only
    ///   on success commit the working chain back and stash the
    ///   skipped keys. Refuses jumps larger than [`MAX_SKIP`].
    ///
    /// All chain mutations are committed only after AEAD has
    /// verified the message — a forged frame leaves the recv
    /// chain untouched.
    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 4 + NONCE_LEN + 16 {
            return Err(anyhow::anyhow!("wire frame too short: {} bytes", wire.len()));
        }
        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&wire[..4]);
        let counter = u32::from_be_bytes(counter_bytes);

        let nonce = Nonce::from_slice(&wire[4..4 + NONCE_LEN]);
        let ct = &wire[4 + NONCE_LEN..];

        // Late delivery of a message whose key we already derived
        // and stashed. The stash is the only path here — any
        // counter older than recv_next that's not in the stash is
        // either a replay or fell off the eviction window.
        if counter < self.recv_next_counter {
            let key = self
                .skipped_message_keys
                .remove(&counter)
                .ok_or_else(|| anyhow::anyhow!(
                    "stale counter {counter} < expected {} (replay or evicted from skip stash)",
                    self.recv_next_counter
                ))?;
            let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
            return cipher
                .decrypt(nonce, Payload { msg: ct, aad })
                .map_err(|e| {
                    // Decrypt failed — the key is gone (we removed
                    // it from the stash above). Stash the key back
                    // so a legitimate retry isn't permanently
                    // locked out by a corrupted-but-noticed frame.
                    self.skipped_message_keys.insert(counter, key);
                    anyhow::anyhow!("aead decrypt (stashed): {e}")
                });
        }

        let skip = counter - self.recv_next_counter;
        if skip > MAX_SKIP {
            return Err(anyhow::anyhow!(
                "counter jumps {} steps ahead; max skip is {}",
                skip,
                MAX_SKIP
            ));
        }

        // Advance a working copy of the recv chain by `skip + 1`
        // steps; collect the skipped keys so we can stash them on
        // success. The working copy is dropped on AEAD failure,
        // leaving self.recv_chain untouched.
        let mut working = self.recv_chain.duplicate();
        let mut pending_skipped: Vec<(u32, Zeroizing<[u8; KEY_LEN]>)> = Vec::new();
        for i in 0..skip {
            let key = working.step()?;
            pending_skipped.push((self.recv_next_counter + i, key));
        }
        let msg_key = working.step()?;

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|e| anyhow::anyhow!("aead decrypt: {e}"))?;
        // msg_key + working zeroise on drop here.

        // Commit. recv_chain advances to the position past
        // `counter`; the skipped keys go into the stash with
        // capacity bookkeeping; recv_next_counter moves to
        // counter + 1.
        self.recv_chain = working;
        for (i, key) in pending_skipped {
            self.stash_message_key(i, key);
        }
        self.recv_next_counter = counter
            .checked_add(1)
            .context("recv counter overflow — re-handshake required")?;
        Ok(pt)
    }

    /// Insert a message key into the skipped-key stash, evicting
    /// the entry with the smallest counter when at capacity. Pure
    /// FIFO-by-counter eviction: simple, predictable, and matches
    /// the "older messages are less likely to still be in flight"
    /// intuition.
    fn stash_message_key(&mut self, counter: u32, key: Zeroizing<[u8; KEY_LEN]>) {
        if self.skipped_message_keys.len() >= MAX_SKIPPED_STASH {
            if let Some(&min_counter) = self.skipped_message_keys.keys().min() {
                self.skipped_message_keys.remove(&min_counter);
            }
        }
        self.skipped_message_keys.insert(counter, key);
    }

    /// Number of message keys currently held in the skipped-key
    /// stash. Exposed so callers (and tests) can monitor the
    /// stash without poking at internals.
    pub fn skipped_stash_len(&self) -> usize {
        self.skipped_message_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (EnhancedHybridRatchet, EnhancedHybridRatchet) {
        let secret = [0x42_u8; 64];
        let init = EnhancedHybridRatchet::from_shared_secret(&secret, RatchetRole::Initiator)
            .expect("init");
        let resp = EnhancedHybridRatchet::from_shared_secret(&secret, RatchetRole::Responder)
            .expect("resp");
        (init, resp)
    }

    #[test]
    fn round_trip_in_order() {
        let (mut a, mut b) = pair();
        for i in 0..50 {
            let msg = format!("hello {i}");
            let wire = a.encrypt(msg.as_bytes(), b"aad").unwrap();
            let pt = b.decrypt(&wire, b"aad").unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn round_trip_both_directions() {
        let (mut a, mut b) = pair();
        let w1 = a.encrypt(b"a->b 1", b"x").unwrap();
        assert_eq!(b.decrypt(&w1, b"x").unwrap(), b"a->b 1");
        let w2 = b.encrypt(b"b->a 1", b"x").unwrap();
        assert_eq!(a.decrypt(&w2, b"x").unwrap(), b"b->a 1");
        let w3 = a.encrypt(b"a->b 2", b"x").unwrap();
        assert_eq!(b.decrypt(&w3, b"x").unwrap(), b"a->b 2");
    }

    #[test]
    fn aad_mismatch_fails() {
        let (mut a, mut b) = pair();
        let wire = a.encrypt(b"secret", b"correct-aad").unwrap();
        assert!(b.decrypt(&wire, b"wrong-aad").is_err());
    }

    #[test]
    fn replay_rejected() {
        let (mut a, mut b) = pair();
        let wire = a.encrypt(b"once", b"").unwrap();
        b.decrypt(&wire, b"").expect("first delivery succeeds");
        // Re-delivering the same wire bytes is rejected: the recv
        // chain has already advanced past that counter.
        assert!(b.decrypt(&wire, b"").is_err());
    }

    #[test]
    fn out_of_order_within_skip_window() {
        let (mut a, mut b) = pair();
        let w0 = a.encrypt(b"m0", b"").unwrap();
        let w1 = a.encrypt(b"m1", b"").unwrap();
        let w2 = a.encrypt(b"m2", b"").unwrap();
        // Receive m2 first — m0 and m1's per-message keys go into
        // the skip stash so the late deliveries can still decrypt.
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"m2");
        assert_eq!(b.skipped_stash_len(), 2);
        // m0 and m1 now arrive in arbitrary order and both work.
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"m1");
        assert_eq!(b.skipped_stash_len(), 1);
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"m0");
        assert_eq!(b.skipped_stash_len(), 0);
        // Re-delivering any of them is rejected — the stash entry
        // is consumed on first successful decrypt.
        assert!(b.decrypt(&w0, b"").is_err());
        assert!(b.decrypt(&w1, b"").is_err());
        assert!(b.decrypt(&w2, b"").is_err());
    }

    #[test]
    fn stash_capped_across_repeated_skip_bursts() {
        // A single decrypt can only stash up to MAX_SKIP - 1
        // entries (the rest of the burst worth of skipped keys)
        // because the per-frame skip cap kicks in first. To exercise
        // the global cap we need several skip-bursts back-to-back.
        let (mut a, mut b) = pair();
        let burst = MAX_SKIP as usize;
        // Each burst sends `burst` messages and delivers only the
        // last, contributing `burst - 1` keys to the stash. Run
        // enough bursts to push past MAX_SKIPPED_STASH.
        let bursts_needed = (MAX_SKIPPED_STASH / (burst - 1)) + 2;
        for _ in 0..bursts_needed {
            let mut wires: Vec<Vec<u8>> = Vec::new();
            for _ in 0..burst {
                wires.push(a.encrypt(b"x", b"").unwrap());
            }
            b.decrypt(wires.last().unwrap(), b"").unwrap();
            assert!(
                b.skipped_stash_len() <= MAX_SKIPPED_STASH,
                "stash blew past cap: {}",
                b.skipped_stash_len()
            );
        }
        assert_eq!(b.skipped_stash_len(), MAX_SKIPPED_STASH);
    }

    #[test]
    fn forged_high_counter_does_not_corrupt_recv_chain() {
        // Pre-stash behaviour: a forged frame with a high counter
        // would step the recv chain past `counter` even when AEAD
        // failed, permanently desynchronising the legitimate
        // sender. The commit-on-success structure leaves the
        // chain (and the stash) untouched on failure.
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"m0", b"").unwrap();
        let m1 = a.encrypt(b"m1", b"").unwrap();

        // Forge a frame with counter 500 and garbage payload.
        let mut forged = Vec::new();
        forged.extend_from_slice(&500u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + 16]);
        assert!(b.decrypt(&forged, b"").is_err());
        assert_eq!(b.skipped_stash_len(), 0, "no keys committed on failure");

        // The legitimate sequence still decrypts in order — the
        // chain wasn't touched.
        assert_eq!(b.decrypt(&m0, b"").unwrap(), b"m0");
        assert_eq!(b.decrypt(&m1, b"").unwrap(), b"m1");
    }

    #[test]
    fn aead_failure_on_stashed_keeps_key_for_retry() {
        // If a stashed key were dropped on AEAD failure, a noisy
        // network that flipped a single bit would lock out the
        // legitimate retry permanently. The stash put-back path
        // keeps the key around so the next clean delivery wins.
        let (mut a, mut b) = pair();
        let w0 = a.encrypt(b"m0", b"").unwrap();
        let w1 = a.encrypt(b"m1", b"").unwrap();
        // Skip-deliver w1 → key for counter 0 lands in the stash.
        b.decrypt(&w1, b"").unwrap();
        assert_eq!(b.skipped_stash_len(), 1);

        // Forge a frame that claims counter 0 but has garbage
        // ciphertext. Decrypt fails and the stash retains the key.
        let mut forged = Vec::new();
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + 16]);
        assert!(b.decrypt(&forged, b"").is_err());
        assert_eq!(b.skipped_stash_len(), 1);

        // The legitimate m0 still decrypts.
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"m0");
        assert_eq!(b.skipped_stash_len(), 0);
    }

    #[test]
    fn refuses_skip_beyond_window() {
        let (mut a, mut b) = pair();
        // Drive `a`'s send counter past MAX_SKIP without delivering
        // anything to `b`.
        for _ in 0..(MAX_SKIP + 1) {
            let _ = a.encrypt(b"x", b"").unwrap();
        }
        let wire = a.encrypt(b"too far", b"").unwrap();
        let err = b.decrypt(&wire, b"").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("max skip"), "unexpected error: {msg}");
    }

    #[test]
    fn rejects_short_frame() {
        let (mut _a, mut b) = pair();
        // 4 + 12 + 16 = 32 bytes is the minimum well-formed frame.
        let too_short = vec![0u8; 31];
        assert!(b.decrypt(&too_short, b"").is_err());
    }

    #[test]
    fn rejects_tiny_secret() {
        let res = EnhancedHybridRatchet::from_shared_secret(&[0u8; 16], RatchetRole::Initiator);
        assert!(res.is_err());
    }

    #[test]
    fn role_swap_breaks_decrypt() {
        // Two peers with the *same* role won't have matching
        // send/recv chains, so decrypt fails before AEAD even runs.
        let secret = [0xAB_u8; 64];
        let mut a = EnhancedHybridRatchet::from_shared_secret(&secret, RatchetRole::Initiator)
            .unwrap();
        let mut a_too = EnhancedHybridRatchet::from_shared_secret(&secret, RatchetRole::Initiator)
            .unwrap();
        let wire = a.encrypt(b"hi", b"").unwrap();
        assert!(a_too.decrypt(&wire, b"").is_err());
    }
}
