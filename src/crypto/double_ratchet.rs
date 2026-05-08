//! Hybrid Double Ratchet built on top of the chain-key construction
//! in [`crate::crypto::enhanced_ratchet`].
//!
//! Adds Signal-style **post-compromise security** (PCS) on top of
//! the chain's forward secrecy: every received message that carries
//! a fresh peer DH public triggers a DH ratchet step, mixing a new
//! X25519 shared secret into the root key and replacing both
//! chains. An attacker who reads ratchet state at time `t` can
//! decrypt messages encrypted under that state — but as soon as one
//! of the peers ratchets (which happens implicitly on send), the
//! root key moves forward through a value the attacker can't
//! compute, and subsequent messages become opaque again.
//!
//! # What this is and isn't
//!
//! This commit lands the **X25519** DH ratchet. The ML-KEM re-encap
//! layer that gives PCS its post-quantum half is a follow-up commit:
//! the wire shape is set up so it can be added without breaking the
//! current format.
//!
//! No header encryption (Signal calls this HE/HEHE mode). The
//! header is bound to AEAD AAD so it can't be tampered with, but
//! it's plaintext on the wire. Adding header encryption would be
//! another layer with its own keys; out of scope here.
//!
//! # Wire format
//!
//! ```text
//! +-----------------+--------------+----------+--------------+--------------------+
//! | sender DH pub   | prev_n (u32) | n (u32)  | nonce (12B)  | AEAD ct + tag      |
//! | 32 B            | BE           | BE       |              |                    |
//! +-----------------+--------------+----------+--------------+--------------------+
//! ```
//!
//! `n` is the sender's counter inside the current DH epoch.
//! `prev_n` is the number of messages they sent in the *previous*
//! epoch — so the receiver knows how many keys to skip+stash from
//! the old recv chain when they detect the DH change. The whole
//! header is fed to ChaCha20-Poly1305 as AAD; tampering with any
//! field invalidates the AEAD tag.
//!
//! # Threat model and known limits
//!
//! * **Forward secrecy**: identical to the chain ratchet — message
//!   keys are derived once and zeroised after use.
//! * **Post-compromise security**: a state read at time `t`
//!   decrypts messages from `t` until the next DH ratchet step
//!   either peer takes. With normal back-and-forth traffic that's
//!   typically one message later.
//! * **Cross-epoch out-of-order**: skipped-key stash is keyed by
//!   `(dh_peer_bytes, counter)` so late deliveries from a previous
//!   epoch still decrypt. Stash capped at [`MAX_SKIPPED_STASH`].
//! * **AEAD failure rollback**: the entire decrypt — including any
//!   triggered DH ratchet step — runs against a working copy of
//!   state. Only a successful AEAD decrypt commits the changes
//!   back to `self`. A forged frame that names a fresh DH header
//!   would otherwise advance the ratchet permanently and lose the
//!   legitimate sender; the snapshot pattern prevents that.
//! * **Not implemented**: per-message DH ratchet (we ratchet per
//!   *epoch*, where an epoch starts on receipt of a new peer DH —
//!   matches Signal's actual cadence, not the colloquial
//!   "per-message"). ML-KEM re-encap layer (b2). Header encryption.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::thread_rng;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::security::secure_rng;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 32 + 4 + 4;
const TAG_LEN: usize = 16;
const MIN_FRAME_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Cap on per-frame skip inside a single DH epoch's recv chain.
/// Same intent as the chain ratchet's MAX_SKIP — bounds attacker-
/// driven CPU per frame.
pub const MAX_SKIP: u32 = 1024;

/// Cap on total stashed message keys across all epochs. Eviction
/// is by smallest counter first — same heuristic as the chain
/// ratchet, on the "older messages are less likely still in
/// flight" intuition.
pub const MAX_SKIPPED_STASH: usize = 4096;

// HKDF info strings. Distinct from the chain ratchet's so an
// attacker who somehow exfiltrates a chain key from one ratchet
// can't replay it against the other.
const INFO_RK: &[u8] = b"qubee/dr/v1/rk";
const INFO_CHAIN_NEXT: &[u8] = b"qubee/dr/v1/chain/next";
const INFO_MESSAGE: &[u8] = b"qubee/dr/v1/chain/msg";

struct ChainKey(SecretBox<[u8; KEY_LEN]>);

impl ChainKey {
    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

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

        self.0 = SecretBox::new(Box::new(next));
        Ok(msg)
    }

    fn duplicate(&self) -> Self {
        Self(SecretBox::new(Box::new(*self.0.expose_secret())))
    }
}

/// Mutable state of a [`DoubleRatchet`]. Lifted into its own struct
/// so `decrypt` can build a working copy, mutate it through the
/// (possibly DH-ratcheting) decrypt path, and only commit back on
/// AEAD success.
struct State {
    root_key: SecretBox<[u8; KEY_LEN]>,
    dh_self_priv: StaticSecret,
    dh_self_pub: PublicKey,
    dh_peer: Option<PublicKey>,
    send_chain: Option<ChainKey>,
    recv_chain: Option<ChainKey>,
    send_counter: u32,
    recv_counter: u32,
    prev_send_counter: u32,
}

impl State {
    fn snapshot(&self) -> Self {
        Self {
            root_key: SecretBox::new(Box::new(*self.root_key.expose_secret())),
            // StaticSecret isn't Clone (it shouldn't be — Clone on a
            // type whose whole purpose is being a secret is a
            // foot-gun). We rebuild via to_bytes/from. Both copies
            // zeroise on drop.
            dh_self_priv: StaticSecret::from(self.dh_self_priv.to_bytes()),
            dh_self_pub: self.dh_self_pub,
            dh_peer: self.dh_peer,
            send_chain: self.send_chain.as_ref().map(|c| c.duplicate()),
            recv_chain: self.recv_chain.as_ref().map(|c| c.duplicate()),
            send_counter: self.send_counter,
            recv_counter: self.recv_counter,
            prev_send_counter: self.prev_send_counter,
        }
    }
}

/// Stash key: scoped to a specific DH epoch so a counter from an
/// old epoch and a counter from a new epoch can both live in the
/// stash without colliding.
#[derive(Clone, Hash, Eq, PartialEq)]
struct SkipKey {
    dh_peer: [u8; KEY_LEN],
    counter: u32,
}

/// Hybrid Double Ratchet (X25519 DH ratchet + chain ratchet).
/// See the module-level docs for the threat model.
pub struct DoubleRatchet {
    state: State,
    skipped: HashMap<SkipKey, Zeroizing<[u8; KEY_LEN]>>,
}

impl DoubleRatchet {
    /// Initiator side. Takes the X3DH/handshake-derived `root_key`
    /// and the responder's published initial DH public — typically
    /// the responder's identity DH key from their prekey bundle.
    /// Generates the initiator's first ratchet keypair and seeds
    /// the send chain by running DH against the peer's pub.
    pub fn initiator(root_key: &[u8; KEY_LEN], peer_initial_dh_pub: PublicKey) -> Result<Self> {
        let dh_self_priv = StaticSecret::random_from_rng(thread_rng());
        let dh_self_pub = PublicKey::from(&dh_self_priv);
        let shared = dh_self_priv.diffie_hellman(&peer_initial_dh_pub);
        let (new_root, send_chain_key) = kdf_rk(root_key, shared.as_bytes())?;

        Ok(Self {
            state: State {
                root_key: SecretBox::new(Box::new(new_root)),
                dh_self_priv,
                dh_self_pub,
                dh_peer: Some(peer_initial_dh_pub),
                send_chain: Some(ChainKey::from_bytes(send_chain_key)),
                recv_chain: None,
                send_counter: 0,
                recv_counter: 0,
                prev_send_counter: 0,
            },
            skipped: HashMap::new(),
        })
    }

    /// Responder side. Takes the same `root_key` the initiator
    /// derived plus the responder's initial ratchet keypair (the
    /// one whose public was advertised in their prekey bundle —
    /// the initiator runs DH against this on their first message).
    /// Send chain isn't ready until the first incoming message
    /// triggers a DH ratchet step.
    pub fn responder(root_key: &[u8; KEY_LEN], own_initial_keypair: StaticSecret) -> Result<Self> {
        let dh_self_pub = PublicKey::from(&own_initial_keypair);
        Ok(Self {
            state: State {
                root_key: SecretBox::new(Box::new(*root_key)),
                dh_self_priv: own_initial_keypair,
                dh_self_pub,
                dh_peer: None,
                send_chain: None,
                recv_chain: None,
                send_counter: 0,
                recv_counter: 0,
                prev_send_counter: 0,
            },
            skipped: HashMap::new(),
        })
    }

    /// Encrypt a message in the current epoch.
    ///
    /// Errors if called on the responder before they've received
    /// the initiator's first message — the responder has no send
    /// chain until the first incoming frame triggers the DH
    /// ratchet step that derives one.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let send_chain = self
            .state
            .send_chain
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!(
                "no send chain: responder must receive the first message before sending"
            ))?;
        let counter = self.state.send_counter;
        let msg_key = send_chain.step()?;
        let nonce_bytes = secure_rng::random::array::<NONCE_LEN>()?;

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(self.state.dh_self_pub.as_bytes());
        header.extend_from_slice(&self.state.prev_send_counter.to_be_bytes());
        header.extend_from_slice(&counter.to_be_bytes());

        let bound_aad = bind_aad(&header, aad);

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &bound_aad })
            .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"))?;

        self.state.send_counter = self
            .state
            .send_counter
            .checked_add(1)
            .context("send counter overflow — re-handshake required")?;

        let mut wire = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Decrypt a message. Drives the full state machine:
    ///
    /// 1. Look up `(header_dh, counter)` in the skipped-key stash;
    ///    a hit means out-of-order delivery for a key we already
    ///    derived in some earlier (possibly older-epoch) decrypt.
    /// 2. Otherwise, if `header_dh` differs from our current
    ///    `dh_peer`, run a DH ratchet step against a working state
    ///    copy: stash any remaining keys in the old recv chain
    ///    (header `prev_n` tells us how many), derive a new root +
    ///    recv chain from `DH(self_priv, header_dh)`, generate a
    ///    fresh send keypair, derive a new root + send chain from
    ///    `DH(new_self_priv, header_dh)`. All on the working copy.
    /// 3. Skip + step the working recv chain to `counter`,
    ///    AEAD-decrypt with the message key. AAD includes the full
    ///    header so any header tampering breaks AEAD.
    /// 4. On AEAD success, commit the working state back to `self`
    ///    and insert pending stash entries. On failure, drop the
    ///    working state and `self` is untouched.
    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < MIN_FRAME_LEN {
            return Err(anyhow::anyhow!("wire frame too short: {} bytes", wire.len()));
        }

        let header = &wire[..HEADER_LEN];
        let header_dh_bytes: [u8; KEY_LEN] = header[..32].try_into().expect("len");
        let header_dh = PublicKey::from(header_dh_bytes);
        let prev_n = u32::from_be_bytes(header[32..36].try_into().expect("len"));
        let counter = u32::from_be_bytes(header[36..40].try_into().expect("len"));

        let nonce = Nonce::from_slice(&wire[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
        let ct = &wire[HEADER_LEN + NONCE_LEN..];

        let bound_aad = bind_aad(header, aad);

        // Stash hit path: cheap, no state mutation. On AEAD failure
        // we put the key back so a clean retry isn't locked out.
        let stash_lookup = SkipKey { dh_peer: header_dh_bytes, counter };
        if let Some(key) = self.skipped.remove(&stash_lookup) {
            let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
            return match cipher.decrypt(nonce, Payload { msg: ct, aad: &bound_aad }) {
                Ok(pt) => Ok(pt),
                Err(e) => {
                    self.skipped.insert(stash_lookup, key);
                    Err(anyhow::anyhow!("aead decrypt (stashed): {e}"))
                }
            };
        }

        // Full path: snapshot state, mutate working copy through
        // any DH ratchet + chain advance, AEAD-decrypt, commit.
        let mut working = self.state.snapshot();
        let mut pending_skipped: Vec<(SkipKey, Zeroizing<[u8; KEY_LEN]>)> = Vec::new();

        let triggers_dh = match working.dh_peer {
            None => true,
            Some(prev) => prev.as_bytes() != &header_dh_bytes,
        };

        if triggers_dh {
            // Skip + stash any remaining keys in the old recv
            // chain. `prev_n` from the header is how many messages
            // the peer sent in their *previous* epoch — i.e. on
            // their old send chain, which is our old recv chain.
            // Anything strictly less than prev_n that we hadn't
            // already received is a candidate for late delivery.
            if let (Some(old_peer_dh), Some(old_recv_chain)) =
                (working.dh_peer, working.recv_chain.as_mut())
            {
                let skip_remaining = prev_n.saturating_sub(working.recv_counter);
                if skip_remaining > MAX_SKIP {
                    return Err(anyhow::anyhow!(
                        "old-epoch tail skip {} exceeds MAX_SKIP {}",
                        skip_remaining,
                        MAX_SKIP,
                    ));
                }
                let old_peer_bytes = *old_peer_dh.as_bytes();
                for i in 0..skip_remaining {
                    let key = old_recv_chain.step()?;
                    pending_skipped.push((
                        SkipKey {
                            dh_peer: old_peer_bytes,
                            counter: working.recv_counter + i,
                        },
                        key,
                    ));
                }
            }

            // DH(self_priv, header_dh) → new root + recv chain.
            let shared_recv = working.dh_self_priv.diffie_hellman(&header_dh);
            let (new_root, recv_chain_key) = kdf_rk(
                working.root_key.expose_secret(),
                shared_recv.as_bytes(),
            )?;
            working.root_key = SecretBox::new(Box::new(new_root));
            working.recv_chain = Some(ChainKey::from_bytes(recv_chain_key));
            working.dh_peer = Some(header_dh);
            working.recv_counter = 0;

            // Generate fresh send keypair and DH against the same
            // header_dh → new root + send chain. The send keypair
            // is what we'll publish in our next outgoing header.
            let new_priv = StaticSecret::random_from_rng(thread_rng());
            let new_pub = PublicKey::from(&new_priv);
            let shared_send = new_priv.diffie_hellman(&header_dh);
            let (new_root2, send_chain_key) = kdf_rk(
                working.root_key.expose_secret(),
                shared_send.as_bytes(),
            )?;
            working.root_key = SecretBox::new(Box::new(new_root2));
            working.dh_self_priv = new_priv;
            working.dh_self_pub = new_pub;
            working.send_chain = Some(ChainKey::from_bytes(send_chain_key));
            working.prev_send_counter = working.send_counter;
            working.send_counter = 0;
        }

        // Now in the current epoch: skip + step recv chain to
        // counter, AEAD-decrypt.
        let recv_chain = working
            .recv_chain
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no recv chain after ratchet step"))?;
        if counter < working.recv_counter {
            return Err(anyhow::anyhow!(
                "stale counter {} in current epoch (expected ≥ {})",
                counter,
                working.recv_counter,
            ));
        }
        let skip = counter - working.recv_counter;
        if skip > MAX_SKIP {
            return Err(anyhow::anyhow!(
                "counter jumps {} steps in current epoch; max skip {}",
                skip,
                MAX_SKIP,
            ));
        }

        let mut working_chain = recv_chain.duplicate();
        for i in 0..skip {
            let key = working_chain.step()?;
            pending_skipped.push((
                SkipKey {
                    dh_peer: header_dh_bytes,
                    counter: working.recv_counter + i,
                },
                key,
            ));
        }
        let msg_key = working_chain.step()?;

        let cipher = ChaCha20Poly1305::new_from_slice(msg_key.as_ref()).expect("32-byte key");
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad: &bound_aad })
            .map_err(|e| anyhow::anyhow!("aead decrypt: {e}"))?;

        // Commit. Working chain replaces the stale one in the
        // working state; working state replaces self.state.
        working.recv_chain = Some(working_chain);
        working.recv_counter = counter
            .checked_add(1)
            .context("recv counter overflow — re-handshake required")?;
        self.state = working;
        for (k, v) in pending_skipped {
            self.stash_message_key(k, v);
        }
        Ok(pt)
    }

    /// Number of message keys currently held in the skipped-key
    /// stash. Exposed for tests and for callers that want to
    /// monitor stash pressure.
    pub fn skipped_stash_len(&self) -> usize {
        self.skipped.len()
    }

    /// Our current outgoing DH public — what would land in the
    /// header of the next encrypted message. Useful for tests
    /// asserting that the DH key actually rotated after a peer
    /// triggered a ratchet step.
    pub fn current_dh_pub(&self) -> PublicKey {
        self.state.dh_self_pub
    }

    fn stash_message_key(&mut self, k: SkipKey, v: Zeroizing<[u8; KEY_LEN]>) {
        if self.skipped.len() >= MAX_SKIPPED_STASH {
            // Evict the smallest-counter entry. Cross-epoch ties
            // (same counter under different DH peers) are broken
            // by HashMap iteration order — fine, both are
            // arbitrary picks at the eviction edge.
            if let Some(min_key) = self.skipped.keys().min_by_key(|k| k.counter).cloned() {
                self.skipped.remove(&min_key);
            }
        }
        self.skipped.insert(k, v);
    }
}

/// HKDF that derives `(new_root, chain_seed)` from `(old_root,
/// dh_output)`. Salt = old root key, IKM = DH output, info =
/// fixed domain string. 64-byte output is split 32:32.
fn kdf_rk(old_root: &[u8; KEY_LEN], dh_output: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
    let hk = Hkdf::<Sha256>::new(Some(old_root), dh_output);
    let mut out = [0u8; KEY_LEN * 2];
    hk.expand(INFO_RK, &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf expand (rk): {e}"))?;
    let mut new_root = [0u8; KEY_LEN];
    let mut chain = [0u8; KEY_LEN];
    new_root.copy_from_slice(&out[..KEY_LEN]);
    chain.copy_from_slice(&out[KEY_LEN..]);
    Ok((new_root, chain))
}

/// Concatenate the wire header with the caller's AAD so AEAD
/// covers both. Tampering with any header field — DH pub, prev_n,
/// counter — invalidates the tag without ever triggering a
/// speculative DH ratchet step on the legitimate receiver, since
/// the snapshot pattern still discards the working state on
/// failure.
fn bind_aad(header: &[u8], caller_aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + caller_aad.len());
    out.extend_from_slice(header);
    out.extend_from_slice(caller_aad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a (initiator, responder) pair sharing the same root
    /// key. Returns the responder's initial DH public so callers
    /// can assert on epoch transitions.
    fn pair() -> (DoubleRatchet, DoubleRatchet, PublicKey) {
        let root = [0xC0_u8; 32];
        let resp_kp = StaticSecret::random_from_rng(thread_rng());
        let resp_pub = PublicKey::from(&resp_kp);
        let init = DoubleRatchet::initiator(&root, resp_pub).unwrap();
        let resp = DoubleRatchet::responder(&root, resp_kp).unwrap();
        (init, resp, resp_pub)
    }

    #[test]
    fn initiator_sends_first_responder_replies() {
        let (mut a, mut b, _) = pair();
        // Responder has no send chain yet.
        assert!(b.encrypt(b"oops", b"").is_err());

        let w1 = a.encrypt(b"hi from a", b"").unwrap();
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"hi from a");
        // After the first DH ratchet on the responder side they
        // can send.
        let w2 = b.encrypt(b"hi back from b", b"").unwrap();
        assert_eq!(a.decrypt(&w2, b"").unwrap(), b"hi back from b");
    }

    #[test]
    fn back_and_forth_runs_dh_ratchet_each_direction_change() {
        let (mut a, mut b, _) = pair();

        let a_pub_0 = a.current_dh_pub();
        let b_pub_0 = b.current_dh_pub();

        let w = a.encrypt(b"a1", b"").unwrap();
        assert_eq!(b.decrypt(&w, b"").unwrap(), b"a1");
        // b's DH key rotated when it processed a's frame.
        assert_ne!(b.current_dh_pub().as_bytes(), b_pub_0.as_bytes());
        // a hasn't rotated yet — it'll rotate when it processes
        // a frame from b's new DH.
        assert_eq!(a.current_dh_pub().as_bytes(), a_pub_0.as_bytes());

        let w = b.encrypt(b"b1", b"").unwrap();
        assert_eq!(a.decrypt(&w, b"").unwrap(), b"b1");
        assert_ne!(a.current_dh_pub().as_bytes(), a_pub_0.as_bytes());

        // Many alternating round-trips, all decrypt cleanly.
        for i in 0..20 {
            let m = format!("a says {i}");
            let w = a.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(b.decrypt(&w, b"").unwrap(), m.as_bytes());
            let m = format!("b says {i}");
            let w = b.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(a.decrypt(&w, b"").unwrap(), m.as_bytes());
        }
    }

    #[test]
    fn many_messages_in_one_direction_use_chain_only() {
        // Sender keeps sending without the receiver replying —
        // chain ratchet does the work, no DH ratchet steps until
        // the receiver eventually sends back.
        let (mut a, mut b, _) = pair();
        for i in 0..50 {
            let m = format!("burst {i}");
            let w = a.encrypt(m.as_bytes(), b"").unwrap();
            assert_eq!(b.decrypt(&w, b"").unwrap(), m.as_bytes());
        }
        // Now b replies — triggers the DH ratchet on a's side.
        let w = b.encrypt(b"finally", b"").unwrap();
        assert_eq!(a.decrypt(&w, b"").unwrap(), b"finally");
    }

    #[test]
    fn out_of_order_within_epoch() {
        let (mut a, mut b, _) = pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();
        let w1 = a.encrypt(b"a1", b"").unwrap();
        let w2 = a.encrypt(b"a2", b"").unwrap();
        // Deliver out of order.
        assert_eq!(b.decrypt(&w2, b"").unwrap(), b"a2");
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"a1");
        assert_eq!(b.skipped_stash_len(), 0);
    }

    #[test]
    fn out_of_order_across_dh_epochs() {
        // The hard case: one or more frames from epoch N arrive
        // *after* a frame from epoch N+1 has already triggered the
        // DH ratchet step. Stash must be keyed by (dh_peer,
        // counter) for this to work.
        let (mut a, mut b, _) = pair();
        let a_w0 = a.encrypt(b"a-old-0", b"").unwrap();
        let a_w1 = a.encrypt(b"a-old-1", b"").unwrap();
        // Deliver a_w1 → b ratchets. a_w0's key goes into the
        // stash for the *old* DH epoch.
        assert_eq!(b.decrypt(&a_w1, b"").unwrap(), b"a-old-1");
        assert!(b.skipped_stash_len() >= 1);

        // b sends a reply, which a will process and ratchet to
        // a new DH epoch.
        let b_w0 = b.encrypt(b"b-new-0", b"").unwrap();
        assert_eq!(a.decrypt(&b_w0, b"").unwrap(), b"b-new-0");

        // Now a's late old-epoch message a_w0 finally arrives at
        // b. The stash holds its key under the old DH peer.
        assert_eq!(b.decrypt(&a_w0, b"").unwrap(), b"a-old-0");
    }

    #[test]
    fn replay_rejected() {
        let (mut a, mut b, _) = pair();
        let w = a.encrypt(b"once", b"").unwrap();
        b.decrypt(&w, b"").unwrap();
        assert!(b.decrypt(&w, b"").is_err());
    }

    #[test]
    fn aad_mismatch_fails() {
        let (mut a, mut b, _) = pair();
        let w = a.encrypt(b"secret", b"correct").unwrap();
        assert!(b.decrypt(&w, b"wrong").is_err());
    }

    #[test]
    fn header_tampering_breaks_aead() {
        // Flip a bit in the header counter. AEAD covers the
        // whole header, so this fails — and the snapshot/commit
        // pattern means the recv chain stays untouched.
        let (mut a, mut b, _) = pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();
        let w1 = a.encrypt(b"a1", b"").unwrap();
        let mut tampered = w1.clone();
        // Flip the lowest bit of the counter field.
        tampered[39] ^= 0x01;
        assert!(b.decrypt(&tampered, b"").is_err());
        // Legitimate sequence still decrypts in order.
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
        assert_eq!(b.decrypt(&w1, b"").unwrap(), b"a1");
    }

    #[test]
    fn forged_dh_does_not_corrupt_state() {
        // A forged frame with a fresh DH header would otherwise
        // trigger a speculative DH ratchet step that the
        // legitimate sender can't recover from. The snapshot
        // pattern leaves state untouched on AEAD failure.
        let (mut a, mut b, _) = pair();
        let w0 = a.encrypt(b"a0", b"").unwrap();

        // Forge a frame with a brand-new DH pub and garbage
        // payload. AEAD will fail.
        let bogus_priv = StaticSecret::random_from_rng(thread_rng());
        let bogus_pub = PublicKey::from(&bogus_priv);
        let mut forged = Vec::new();
        forged.extend_from_slice(bogus_pub.as_bytes());
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&0u32.to_be_bytes());
        forged.extend_from_slice(&[0u8; NONCE_LEN]);
        forged.extend_from_slice(&[0u8; 32 + TAG_LEN]);
        assert!(b.decrypt(&forged, b"").is_err());

        // Legitimate frame still decrypts; state was rolled back.
        assert_eq!(b.decrypt(&w0, b"").unwrap(), b"a0");
    }

    #[test]
    fn refuses_oversize_skip_inside_epoch() {
        let (mut a, mut b, _) = pair();
        // Send MAX_SKIP+1 messages without delivering any →
        // a.send_counter = MAX_SKIP+1. The next encrypt produces
        // counter = MAX_SKIP+1, giving b a skip of MAX_SKIP+1
        // against its recv_counter=0, which exceeds the cap.
        for _ in 0..(MAX_SKIP + 1) {
            let _ = a.encrypt(b"x", b"").unwrap();
        }
        let w = a.encrypt(b"too-far", b"").unwrap();
        assert!(b.decrypt(&w, b"").is_err());
    }

    #[test]
    fn rejects_short_frame() {
        let (_a, mut b, _) = pair();
        let too_short = vec![0u8; MIN_FRAME_LEN - 1];
        assert!(b.decrypt(&too_short, b"").is_err());
    }
}
