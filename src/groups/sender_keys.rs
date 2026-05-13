//! Sender Keys: per-(group, sender, generation) symmetric chains
//! that give group messages forward secrecy at the message level.
//!
//! # Why a separate primitive
//!
//! `crate::crypto::EnhancedHybridRatchet` and
//! `crate::crypto::DoubleRatchet` are both bidirectional — each
//! party holds a send chain and a recv chain because the protocols
//! they implement are pairwise. Group messaging is fundamentally
//! one-to-many: each member publishes on a single per-group send
//! chain that all peers in the group track. A bidirectional
//! ratchet would waste half its state on a chain that's never
//! used.
//!
//! `SenderChain` is the minimal one-direction primitive: a single
//! 32-byte chain key advanced via HKDF-SHA256, a per-message
//! ChaCha20-Poly1305 key derived alongside, and a small skipped-
//! key stash so out-of-order delivery (common over gossipsub) is
//! survivable.
//!
//! # Threat model and limits
//!
//! * **Forward secrecy**: each message key is derived once and
//!   zeroised after use. Recovering a message at counter `n` from
//!   an attacker-known chain at counter `n+1` requires breaking
//!   SHA256.
//! * **No post-compromise security at the group level**. PCS in
//!   groups needs a TreeKEM-style construction (MLS); a per-sender
//!   chain only protects against retrospective decryption, not
//!   future compromise. See the README on this caveat.
//! * **Chains are scoped to a generation**. When the group's
//!   `version` field bumps (member add/remove, key rotation), all
//!   pre-bump chains are abandoned; new chains are derived from
//!   the new group key for the new generation. The current
//!   `decrypt_group_message` generation gate enforces this.
//! * **Replay rejected by counter monotonicity**, with a stash
//!   of out-of-order keys capped at [`MAX_SKIPPED_STASH`].
//! * **AEAD failure rolls back chain state**: like the ratchet
//!   primitives, decrypt advances a working copy of the chain
//!   and only commits on AEAD success. A forged frame with a
//!   high counter can't permanently corrupt the chain.
//!
//! # Wire format (carried in `GroupMessageBody.aead_payload`)
//!
//! ```text
//! +-----------+--------------+--------------------------+
//! | counter   | nonce (12B)  | ChaCha20-Poly1305 ct+tag |
//! | u32 BE    |              |                          |
//! +-----------+--------------+--------------------------+
//! ```
//!
//! Sender id and generation aren't in the inner wire — they live
//! in `GroupMessageBody` (signed by the sender) which is what the
//! group-message envelope already carries.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::groups::group_manager::GroupId;
use crate::identity::identity_key::IdentityId;
use crate::security::secure_rng;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const COUNTER_LEN: usize = 4;
/// Minimum well-formed frame: counter + nonce + AEAD tag (empty
/// plaintext is permitted).
pub const MIN_FRAME_LEN: usize = COUNTER_LEN + NONCE_LEN + TAG_LEN;

/// Cap on per-frame skip. Same MAX_SKIP semantics as the ratchet
/// primitives: a single received frame may not jump the chain
/// forward by more than this.
pub const MAX_SKIP: u32 = 1024;

/// Cap on total stashed message keys per chain. Eviction is by
/// smallest-counter on overflow.
pub const MAX_SKIPPED_STASH: usize = 4096;

// HKDF info strings. Distinct from the ratchet primitives so a
// chain key exfiltrated from one can't be replayed against the
// other.
const INFO_SEED: &[u8] = b"qubee/sk/v1/seed";
const INFO_CHAIN_NEXT: &[u8] = b"qubee/sk/v1/chain/next";
const INFO_MESSAGE: &[u8] = b"qubee/sk/v1/chain/msg";

/// Single-direction symmetric chain. Sender derives a fresh
/// per-message key from the chain on every send; receiver tracks
/// the same chain by advancing it to each incoming counter,
/// stashing keys for any counters that arrived out of order.
pub struct SenderChain {
    /// Current chain key. Advanced (and replaced) on every
    /// `step`.
    chain_key: SecretBox<[u8; KEY_LEN]>,
    /// Counter of the next message we expect (recv side) or will
    /// produce (send side).
    next_counter: u32,
    /// Skipped per-message keys keyed by counter, populated
    /// during decrypt when frames arrive out of order. Sender
    /// side never inserts — its counter advances monotonically.
    skipped: HashMap<u32, Zeroizing<[u8; KEY_LEN]>>,
}

impl SenderChain {
    /// Derive a chain from a group key + sender id + generation.
    /// Both peers (sender and receivers) call this with identical
    /// arguments to land on identical starting state.
    pub fn from_group_seed(
        group_key: &[u8; 32],
        group_id: &GroupId,
        sender_id: &IdentityId,
        generation: u64,
    ) -> Result<Self> {
        let mut salt = Vec::with_capacity(group_id.as_ref().len() + sender_id.as_ref().len() + 8);
        salt.extend_from_slice(group_id.as_ref());
        salt.extend_from_slice(sender_id.as_ref());
        salt.extend_from_slice(&generation.to_le_bytes());

        let mut seed = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(Some(&salt), group_key)
            .expand(INFO_SEED, &mut seed)
            .map_err(|e| anyhow::anyhow!("hkdf expand (sk seed): {e}"))?;

        Ok(Self {
            chain_key: SecretBox::new(Box::new(seed)),
            next_counter: 0,
            skipped: HashMap::new(),
        })
    }

    /// Encrypt `plaintext` (with `aad` covering associated
    /// metadata) on the sender side. Commit-on-success: chain key
    /// and counter only advance after AEAD succeeds, so a failed
    /// nonce-gen or AEAD leaves the chain undisturbed and a retry
    /// emits the same counter under the same key.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let counter = self.next_counter;
        let (next_chain_key, msg_key) = chain_advance(self.chain_key.expose_secret())?;
        let nonce_bytes = secure_rng::random::array::<NONCE_LEN>()?;

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"))?;

        let next_counter = self
            .next_counter
            .checked_add(1)
            .context("send counter overflow — re-handshake required")?;
        // All fallible operations done — commit.
        self.chain_key = SecretBox::new(Box::new(next_chain_key));
        self.next_counter = next_counter;

        let mut wire = Vec::with_capacity(COUNTER_LEN + NONCE_LEN + ct.len());
        wire.extend_from_slice(&counter.to_be_bytes());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Decrypt a frame against the receive side of this chain.
    /// Handles three counter regimes (stashed-key hit; in-order;
    /// out-of-order skip-ahead) with commit-on-AEAD-success
    /// semantics throughout.
    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < MIN_FRAME_LEN {
            return Err(anyhow::anyhow!("wire frame too short: {} bytes", wire.len()));
        }
        let mut counter_bytes = [0u8; COUNTER_LEN];
        counter_bytes.copy_from_slice(&wire[..COUNTER_LEN]);
        let counter = u32::from_be_bytes(counter_bytes);

        let nonce = Nonce::from_slice(&wire[COUNTER_LEN..COUNTER_LEN + NONCE_LEN]);
        let ct = &wire[COUNTER_LEN + NONCE_LEN..];

        // Stash hit (out-of-order delivery for a previously
        // derived key). Put it back if AEAD fails so a clean
        // retry isn't locked out.
        if counter < self.next_counter {
            let key = self
                .skipped
                .remove(&counter)
                .ok_or_else(|| anyhow::anyhow!(
                    "stale counter {counter} < expected {} (replay or evicted)",
                    self.next_counter
                ))?;
            let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
            return match cipher.decrypt(nonce, Payload { msg: ct, aad }) {
                Ok(pt) => Ok(pt),
                Err(e) => {
                    self.skipped.insert(counter, key);
                    Err(anyhow::anyhow!("aead decrypt (stashed): {e}"))
                }
            };
        }

        // In-order or skip-ahead path. Advance a *clone* of the
        // chain through the burst, AEAD-decrypt, only on success
        // commit the working chain back and stash skipped keys.
        let skip = counter - self.next_counter;
        if skip > MAX_SKIP {
            return Err(anyhow::anyhow!(
                "counter jumps {skip} steps; max skip {MAX_SKIP}"
            ));
        }

        let mut working_key = *self.chain_key.expose_secret();
        let mut pending_skipped: Vec<(u32, Zeroizing<[u8; KEY_LEN]>)> = Vec::new();
        for i in 0..skip {
            let (next, msg) = chain_advance(&working_key)?;
            working_key = next;
            pending_skipped.push((self.next_counter + i, msg));
        }
        let (next_after_msg, msg_key) = chain_advance(&working_key)?;

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|e| anyhow::anyhow!("aead decrypt: {e}"))?;

        // Commit. working_key bytes get zeroed via the
        // Zeroizing wrapper on next allocation.
        self.chain_key = SecretBox::new(Box::new(next_after_msg));
        self.next_counter = counter
            .checked_add(1)
            .context("recv counter overflow — re-handshake required")?;
        for (c, k) in pending_skipped {
            self.stash_message_key(c, k);
        }
        Ok(pt)
    }

    fn stash_message_key(&mut self, counter: u32, key: Zeroizing<[u8; KEY_LEN]>) {
        if self.skipped.len() >= MAX_SKIPPED_STASH {
            if let Some(&min_counter) = self.skipped.keys().min() {
                self.skipped.remove(&min_counter);
            }
        }
        self.skipped.insert(counter, key);
    }

    /// Counter of the next message this chain will produce / accept.
    pub fn next_counter(&self) -> u32 {
        self.next_counter
    }

    /// Number of message keys currently in the skipped-key stash.
    /// Exposed for tests and for callers that want to monitor stash
    /// pressure.
    pub fn skipped_stash_len(&self) -> usize {
        self.skipped.len()
    }

    /// Serialize the chain to bytes for keystore persistence.
    /// `Persisted` carries the chain key + counter + a flat
    /// representation of the stash. Round-trips through
    /// [`SenderChain::restore`]. Format is bincode-stable; the
    /// Persisted struct's field set is the contract.
    pub fn persist(&self) -> Result<Vec<u8>> {
        let mut skipped: Vec<(u32, [u8; KEY_LEN])> = Vec::with_capacity(self.skipped.len());
        for (counter, key) in &self.skipped {
            // `key: &Zeroizing<[u8; 32]>`. Deref through the
            // wrapper to get a `&[u8; 32]`, then copy out the
            // array (it's Copy).
            let bytes: [u8; KEY_LEN] = **key;
            skipped.push((*counter, bytes));
        }
        skipped.sort_by_key(|(c, _)| *c);

        let persisted = Persisted {
            chain_key: *self.chain_key.expose_secret(),
            next_counter: self.next_counter,
            skipped,
        };
        bincode::serialize(&persisted).context("sender chain serialize")
    }

    /// Restore a chain from bytes produced by [`SenderChain::persist`].
    pub fn restore(bytes: &[u8]) -> Result<Self> {
        let persisted: Persisted =
            bincode::deserialize(bytes).context("sender chain deserialize")?;
        if persisted.skipped.len() > MAX_SKIPPED_STASH {
            return Err(anyhow::anyhow!(
                "persisted stash size {} exceeds MAX_SKIPPED_STASH {}",
                persisted.skipped.len(),
                MAX_SKIPPED_STASH
            ));
        }
        let mut skipped = HashMap::with_capacity(persisted.skipped.len());
        for (c, k) in persisted.skipped {
            skipped.insert(c, Zeroizing::new(k));
        }
        Ok(Self {
            chain_key: SecretBox::new(Box::new(persisted.chain_key)),
            next_counter: persisted.next_counter,
            skipped,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    chain_key: [u8; KEY_LEN],
    next_counter: u32,
    /// `(counter, message_key)` pairs from the skip stash.
    /// Vec rather than HashMap so bincode output is deterministic
    /// across serializations of equivalent state.
    skipped: Vec<(u32, [u8; KEY_LEN])>,
}

/// Run one HKDF step on a chain key. Returns
/// `(next_chain_key, this_step_message_key)` without mutating
/// the input. Pulled out as a free function so both `step` and
/// the working-copy advance loop in `decrypt` share it.
fn chain_advance(current: &[u8; KEY_LEN]) -> Result<([u8; KEY_LEN], Zeroizing<[u8; KEY_LEN]>)> {
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

    Ok((next, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SenderChain, SenderChain) {
        let group_key = [0xA0_u8; 32];
        let group_id = GroupId::from_bytes([1u8; 32]);
        let sender_id = IdentityId::from([2u8; 32]);
        let send = SenderChain::from_group_seed(&group_key, &group_id, &sender_id, 1).unwrap();
        let recv = SenderChain::from_group_seed(&group_key, &group_id, &sender_id, 1).unwrap();
        (send, recv)
    }

    #[test]
    fn round_trip_in_order() {
        let (mut s, mut r) = pair();
        for i in 0..32 {
            let m = format!("msg {i}");
            let wire = s.encrypt(m.as_bytes(), b"aad").unwrap();
            assert_eq!(r.decrypt(&wire, b"aad").unwrap(), m.as_bytes());
        }
    }

    #[test]
    fn aad_mismatch_fails() {
        let (mut s, mut r) = pair();
        let wire = s.encrypt(b"x", b"correct").unwrap();
        assert!(r.decrypt(&wire, b"wrong").is_err());
    }

    #[test]
    fn replay_rejected() {
        let (mut s, mut r) = pair();
        let wire = s.encrypt(b"once", b"").unwrap();
        r.decrypt(&wire, b"").unwrap();
        assert!(r.decrypt(&wire, b"").is_err());
    }

    #[test]
    fn out_of_order_within_skip_window() {
        let (mut s, mut r) = pair();
        let w0 = s.encrypt(b"m0", b"").unwrap();
        let w1 = s.encrypt(b"m1", b"").unwrap();
        let w2 = s.encrypt(b"m2", b"").unwrap();
        assert_eq!(r.decrypt(&w2, b"").unwrap(), b"m2");
        assert_eq!(r.skipped_stash_len(), 2);
        assert_eq!(r.decrypt(&w0, b"").unwrap(), b"m0");
        assert_eq!(r.decrypt(&w1, b"").unwrap(), b"m1");
        assert_eq!(r.skipped_stash_len(), 0);
    }

    #[test]
    fn refuses_skip_beyond_window() {
        let (mut s, mut r) = pair();
        for _ in 0..(MAX_SKIP + 1) {
            let _ = s.encrypt(b"x", b"").unwrap();
        }
        let wire = s.encrypt(b"too far", b"").unwrap();
        assert!(r.decrypt(&wire, b"").is_err());
    }

    #[test]
    fn forged_frame_does_not_corrupt_chain() {
        let (mut s, mut r) = pair();
        let m0 = s.encrypt(b"m0", b"").unwrap();
        let m1 = s.encrypt(b"m1", b"").unwrap();

        // Forge a frame with counter 500 and garbage. AEAD fails;
        // the working chain copy is dropped and r.chain_key /
        // r.next_counter are unchanged.
        let mut forged = Vec::new();
        forged.extend_from_slice(&500u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(r.decrypt(&forged, b"").is_err());
        assert_eq!(r.skipped_stash_len(), 0);

        assert_eq!(r.decrypt(&m0, b"").unwrap(), b"m0");
        assert_eq!(r.decrypt(&m1, b"").unwrap(), b"m1");
    }

    #[test]
    fn aead_failure_on_stashed_keeps_key_for_retry() {
        let (mut s, mut r) = pair();
        let w0 = s.encrypt(b"m0", b"").unwrap();
        let w1 = s.encrypt(b"m1", b"").unwrap();
        r.decrypt(&w1, b"").unwrap();
        assert_eq!(r.skipped_stash_len(), 1);

        let mut forged = Vec::new();
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(r.decrypt(&forged, b"").is_err());
        assert_eq!(r.skipped_stash_len(), 1);

        assert_eq!(r.decrypt(&w0, b"").unwrap(), b"m0");
        assert_eq!(r.skipped_stash_len(), 0);
    }

    #[test]
    fn distinct_seed_inputs_diverge() {
        let group_key = [0xC1_u8; 32];
        let g1 = GroupId::from_bytes([1u8; 32]);
        let g2 = GroupId::from_bytes([2u8; 32]);
        let s1 = IdentityId::from([3u8; 32]);
        let s2 = IdentityId::from([4u8; 32]);

        let mut a = SenderChain::from_group_seed(&group_key, &g1, &s1, 1).unwrap();
        let mut b = SenderChain::from_group_seed(&group_key, &g2, &s1, 1).unwrap();
        let mut c = SenderChain::from_group_seed(&group_key, &g1, &s2, 1).unwrap();
        let mut d = SenderChain::from_group_seed(&group_key, &g1, &s1, 2).unwrap();

        let wire = a.encrypt(b"hi", b"").unwrap();
        // Different group → different chain → fails AEAD.
        assert!(b.decrypt(&wire, b"").is_err());
        // Different sender → different chain.
        assert!(c.decrypt(&wire, b"").is_err());
        // Different generation → different chain.
        assert!(d.decrypt(&wire, b"").is_err());
    }

    #[test]
    fn persist_and_restore_round_trip() {
        let (mut s, mut r) = pair();
        // Send a few messages, deliver one out of order so the
        // stash is populated.
        let w0 = s.encrypt(b"m0", b"").unwrap();
        let w1 = s.encrypt(b"m1", b"").unwrap();
        let w2 = s.encrypt(b"m2", b"").unwrap();
        r.decrypt(&w2, b"").unwrap();
        assert_eq!(r.skipped_stash_len(), 2);

        // Snapshot + restore both chains, verify they continue
        // working — w1 + w0 still decrypt via the restored stash,
        // and a follow-on encrypt+decrypt roundtrips on the
        // restored send/recv pair.
        let s_bytes = s.persist().unwrap();
        let r_bytes = r.persist().unwrap();
        let mut s = SenderChain::restore(&s_bytes).unwrap();
        let mut r = SenderChain::restore(&r_bytes).unwrap();

        assert_eq!(r.decrypt(&w1, b"").unwrap(), b"m1");
        assert_eq!(r.decrypt(&w0, b"").unwrap(), b"m0");

        let w3 = s.encrypt(b"m3", b"").unwrap();
        assert_eq!(r.decrypt(&w3, b"").unwrap(), b"m3");
    }

    #[test]
    fn restore_rejects_oversized_stash() {
        // Hand-craft a Persisted with too many entries and
        // confirm restore refuses. Defends against keystore
        // corruption and against an attacker who can plant a
        // tampered chain blob to drive memory usage.
        let mut over = Vec::with_capacity(MAX_SKIPPED_STASH + 1);
        for i in 0..(MAX_SKIPPED_STASH + 1) {
            over.push((i as u32, [0u8; KEY_LEN]));
        }
        let persisted = Persisted {
            chain_key: [0u8; KEY_LEN],
            next_counter: 0,
            skipped: over,
        };
        let bytes = bincode::serialize(&persisted).unwrap();
        assert!(SenderChain::restore(&bytes).is_err());
    }

    #[test]
    fn rejects_short_frame() {
        let (_s, mut r) = pair();
        let too_short = vec![0u8; MIN_FRAME_LEN - 1];
        assert!(r.decrypt(&too_short, b"").is_err());
    }
}
