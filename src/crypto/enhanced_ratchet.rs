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
//! Skipped-message keys are *not* stashed: messages that arrive
//! out of order but inside the skip window advance the chain past
//! them (so they're decrypt-able the first time but not after) and
//! intermediate counters are silently consumed. A future revision
//! that needs Signal-style replay-tolerance can store a
//! `HashMap<u32, MessageKey>` of skipped keys.
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
use zeroize::Zeroize;

use crate::security::secure_rng;

/// Cap on how far ahead a single received message may jump the
/// recv chain. 1024 lets a peer absorb a moderate burst of out-of-
/// order delivery (e.g. a sender unblocking after a network stall)
/// while keeping the worst-case work per packet bounded.
pub const MAX_SKIP: u32 = 1024;

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
    fn step(&mut self) -> Result<[u8; KEY_LEN]> {
        let current = self.0.expose_secret();

        let mut next = [0u8; KEY_LEN];
        Hkdf::<Sha256>::from_prk(current)
            .map_err(|e| anyhow::anyhow!("hkdf prk (chain): {e}"))?
            .expand(INFO_CHAIN_NEXT, &mut next)
            .map_err(|e| anyhow::anyhow!("hkdf expand (chain): {e}"))?;

        let mut msg = [0u8; KEY_LEN];
        Hkdf::<Sha256>::from_prk(current)
            .map_err(|e| anyhow::anyhow!("hkdf prk (msg): {e}"))?
            .expand(INFO_MESSAGE, &mut msg)
            .map_err(|e| anyhow::anyhow!("hkdf expand (msg): {e}"))?;

        // Replace self with the new chain key. The previous chain
        // key bytes are zeroised when the old SecretBox is
        // dropped.
        self.0 = SecretBox::new(Box::new(next));
        Ok(msg)
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
        })
    }

    /// Encrypt a message. Wire bytes carry the counter and nonce so
    /// the peer can identify which chain step to advance to.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let counter = self.send_counter;
        let mut msg_key = self.send_chain.step()?;
        let nonce_bytes = secure_rng::random::array::<NONCE_LEN>()?;

        let cipher = ChaCha20Poly1305::new_from_slice(&msg_key).expect("32-byte key");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"));

        // Wipe the per-message key whether or not encrypt succeeded.
        msg_key.zeroize();
        let ct = ct?;

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

    /// Decrypt a message. Refuses counters that would jump the
    /// recv chain forward by more than [`MAX_SKIP`], or that are
    /// older than the current recv position (replay).
    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 4 + NONCE_LEN + 16 {
            return Err(anyhow::anyhow!("wire frame too short: {} bytes", wire.len()));
        }
        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&wire[..4]);
        let counter = u32::from_be_bytes(counter_bytes);

        if counter < self.recv_next_counter {
            return Err(anyhow::anyhow!(
                "stale counter {} < expected {} (replay or out-of-order beyond skip window)",
                counter,
                self.recv_next_counter
            ));
        }
        let skip = counter - self.recv_next_counter;
        if skip > MAX_SKIP {
            return Err(anyhow::anyhow!(
                "counter jumps {} steps ahead; max skip is {}",
                skip,
                MAX_SKIP
            ));
        }

        // Advance the recv chain past any skipped counters,
        // discarding their per-message keys. Messages with those
        // counters that arrive later will fail the staleness check
        // above. A Signal-style implementation would stash the
        // skipped keys here; we deliberately don't.
        for _ in 0..skip {
            let mut burned = self.recv_chain.step()?;
            burned.zeroize();
        }

        let mut msg_key = self.recv_chain.step()?;
        let nonce = Nonce::from_slice(&wire[4..4 + NONCE_LEN]);
        let ct = &wire[4 + NONCE_LEN..];

        let cipher = ChaCha20Poly1305::new_from_slice(&msg_key).expect("32-byte key");
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|e| anyhow::anyhow!("aead decrypt: {e}"));
        msg_key.zeroize();
        let pt = pt?;

        self.recv_next_counter = counter
            .checked_add(1)
            .context("recv counter overflow — re-handshake required")?;
        Ok(pt)
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
        // Receive m2 first — burns m0 and m1's keys but
        // succeeds.
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"m2");
        // m0 and m1 now arrive late and are rejected as stale.
        assert!(b.decrypt(&w0, b"").is_err());
        assert!(b.decrypt(&w1, b"").is_err());
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
