//! Per-peer 1:1 direct-message sessions, layered on the
//! [`crate::crypto::DoubleRatchet`] primitive.
//!
//! A [`DmSession`] is a single conversation between two
//! identities. It owns one Double Ratchet instance plus the peer
//! identity it's bound to, and exposes the encrypt/decrypt
//! methods the rest of the stack uses.
//!
//! [`SessionManager`] holds the local member's DM sessions
//! keyed by peer [`IdentityId`]. It's the moral equivalent of
//! [`crate::groups::GroupManager`] for pairwise traffic — same
//! ownership model (one per process, mutex-guarded at the JNI
//! boundary), same lifecycle, distinct wire format.
//!
//! # Threat model
//!
//! Inherits everything `DoubleRatchet` provides:
//!
//! * **Forward secrecy** at message granularity (chain ratchet).
//! * **Post-compromise security** on every direction change
//!   (X25519 DH ratchet).
//! * **Post-quantum forward secrecy** when hybrid mode is opted
//!   in via [`DmSession::establish_initiator_hybrid`] /
//!   [`DmSession::establish_responder_hybrid`] (ML-KEM-768
//!   re-encap).
//! * **Header confidentiality + traffic-analysis resistance**
//!   from the rotating-header-key HEHE layer.
//!
//! # What this commit doesn't include
//!
//! * **Persistence**: sessions live in process memory only.
//!   Restart resets all session state and breaks decryption of
//!   in-flight peer frames until a fresh handshake. Wiring
//!   `DoubleRatchet::persist`/`restore` into the keystore
//!   (analogous to the sender-chain flow) is the (3b) follow-up.
//! * **Handshake**: the constructors take a pre-derived
//!   `root_key` and the peer's initial DH public key (initiator)
//!   or our own initial DH keypair (responder). Producing those
//!   from a real X3DH-style handshake (Kyber + signed prekey
//!   bundle, etc.) is the work of `crate::groups::group_handshake`'s
//!   pairwise sibling — also (3b) territory.
//! * **JNI bridge**: no `nativeOpenDmSession`/`nativeEncryptDm`
//!   surface yet. `crate::jni_api` doesn't see this module.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use x25519_dalek::{PublicKey as DhPublicKey, StaticSecret as DhStaticSecret};

use crate::crypto::{double_ratchet::KyberConfig, DoubleRatchet};
use crate::identity::identity_key::IdentityId;

/// Single 1:1 DM session. Wraps a [`DoubleRatchet`] plus the
/// peer identity it's bound to. Encrypt/decrypt delegate to the
/// ratchet; the peer id is carried so the [`SessionManager`]
/// can look up the right session for an incoming frame.
pub struct DmSession {
    peer_id: IdentityId,
    ratchet: DoubleRatchet,
}

impl DmSession {
    /// Initiator side. The caller has derived `root_key` from a
    /// pairwise handshake (X3DH-style; not yet implemented in
    /// this crate, see module docs) and knows the peer's published
    /// initial DH public key.
    pub fn establish_initiator(
        peer_id: IdentityId,
        root_key: &[u8; 32],
        peer_initial_dh_pub: DhPublicKey,
    ) -> Result<Self> {
        let ratchet = DoubleRatchet::initiator(root_key, peer_initial_dh_pub)?;
        Ok(Self { peer_id, ratchet })
    }

    /// Initiator side, hybrid mode (X25519 + periodic ML-KEM-768
    /// re-encap on every DH ratchet step).
    pub fn establish_initiator_hybrid(
        peer_id: IdentityId,
        root_key: &[u8; 32],
        peer_initial_dh_pub: DhPublicKey,
        kyber: KyberConfig,
    ) -> Result<Self> {
        let ratchet = DoubleRatchet::initiator_hybrid(root_key, peer_initial_dh_pub, kyber)?;
        Ok(Self { peer_id, ratchet })
    }

    /// Responder side. The caller has the same `root_key` the
    /// initiator derived (output of the same handshake) plus the
    /// initial DH keypair whose public was published in the
    /// pre-key bundle.
    pub fn establish_responder(
        peer_id: IdentityId,
        root_key: &[u8; 32],
        own_initial_keypair: DhStaticSecret,
    ) -> Result<Self> {
        let ratchet = DoubleRatchet::responder(root_key, own_initial_keypair)?;
        Ok(Self { peer_id, ratchet })
    }

    /// Responder side, hybrid mode.
    pub fn establish_responder_hybrid(
        peer_id: IdentityId,
        root_key: &[u8; 32],
        own_initial_keypair: DhStaticSecret,
        kyber: KyberConfig,
    ) -> Result<Self> {
        let ratchet =
            DoubleRatchet::responder_hybrid(root_key, own_initial_keypair, kyber)?;
        Ok(Self { peer_id, ratchet })
    }

    /// Identity of the peer this session is bound to.
    pub fn peer_id(&self) -> &IdentityId {
        &self.peer_id
    }

    /// Encrypt a plaintext message to this peer. AAD is bound
    /// at both Double Ratchet layers (header AEAD + body AEAD);
    /// callers should pass canonical metadata bytes that the
    /// receiver can reproduce.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.ratchet.encrypt(plaintext, aad)
    }

    /// Decrypt a wire frame received from this peer.
    pub fn decrypt(&mut self, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.ratchet.decrypt(wire, aad)
    }
}

/// Process-wide registry of DM sessions, keyed by peer
/// [`IdentityId`]. Mirrors [`crate::groups::GroupManager`]'s role
/// but for pairwise traffic.
pub struct SessionManager {
    sessions: HashMap<IdentityId, DmSession>,
}

impl SessionManager {
    /// Empty manager. Sessions are added via the
    /// `establish_*` methods.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Open a new initiator-side session against `peer_id`.
    /// Returns an error if a session for that peer already
    /// exists — callers must explicitly drop the old session
    /// (via [`drop_session`]) before re-handshaking.
    pub fn establish_initiator(
        &mut self,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        peer_initial_dh_pub: DhPublicKey,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id) {
            return Err(anyhow!(
                "session for peer already exists; drop it first"
            ));
        }
        let session = DmSession::establish_initiator(peer_id, root_key, peer_initial_dh_pub)?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Open a new initiator-side session in hybrid mode.
    pub fn establish_initiator_hybrid(
        &mut self,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        peer_initial_dh_pub: DhPublicKey,
        kyber: KyberConfig,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id) {
            return Err(anyhow!(
                "session for peer already exists; drop it first"
            ));
        }
        let session = DmSession::establish_initiator_hybrid(
            peer_id,
            root_key,
            peer_initial_dh_pub,
            kyber,
        )?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Open a new responder-side session against `peer_id`.
    pub fn establish_responder(
        &mut self,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        own_initial_keypair: DhStaticSecret,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id) {
            return Err(anyhow!(
                "session for peer already exists; drop it first"
            ));
        }
        let session = DmSession::establish_responder(peer_id, root_key, own_initial_keypair)?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Open a new responder-side session in hybrid mode.
    pub fn establish_responder_hybrid(
        &mut self,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        own_initial_keypair: DhStaticSecret,
        kyber: KyberConfig,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id) {
            return Err(anyhow!(
                "session for peer already exists; drop it first"
            ));
        }
        let session = DmSession::establish_responder_hybrid(
            peer_id,
            root_key,
            own_initial_keypair,
            kyber,
        )?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Whether we hold a session for `peer_id`. Useful at the
    /// JNI boundary to decide between "encrypt as DM" and
    /// "kick off a handshake first".
    pub fn has_session(&self, peer_id: &IdentityId) -> bool {
        self.sessions.contains_key(peer_id)
    }

    /// Encrypt a plaintext message to `peer_id`. Errors if no
    /// session exists for that peer.
    pub fn encrypt(
        &mut self,
        peer_id: &IdentityId,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| anyhow!("no DM session for peer"))?;
        session.encrypt(plaintext, aad)
    }

    /// Decrypt an incoming frame from `peer_id`. Errors if no
    /// session exists for that peer.
    pub fn decrypt(
        &mut self,
        peer_id: &IdentityId,
        wire: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| anyhow!("no DM session for peer"))?;
        session.decrypt(wire, aad)
    }

    /// Drop the session for `peer_id` (e.g. before re-handshake
    /// or after the peer revokes their identity). Returns `true`
    /// if a session existed.
    pub fn drop_session(&mut self, peer_id: &IdentityId) -> bool {
        self.sessions.remove(peer_id).is_some()
    }

    /// Number of currently open sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// True if no sessions are open.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_root_key() -> [u8; 32] {
        // In production this comes from an X3DH/PQXDH handshake.
        // Tests just hand both peers the same bytes.
        [0xD3_u8; 32]
    }

    fn dm_pair() -> (SessionManager, SessionManager, IdentityId, IdentityId) {
        // Both peers' identity ids — arbitrary, just need to be
        // distinct and consistent across the test.
        let alice_id = IdentityId::from([1u8; 32]);
        let bob_id = IdentityId::from([2u8; 32]);

        // Bob's "initial DH keypair" — what would be advertised
        // in a real prekey bundle.
        let bob_initial_priv = DhStaticSecret::random_from_rng(rand::thread_rng());
        let bob_initial_pub = DhPublicKey::from(&bob_initial_priv);

        let root = shared_root_key();
        let mut alice = SessionManager::new();
        alice
            .establish_initiator(bob_id, &root, bob_initial_pub)
            .expect("alice init");
        let mut bob = SessionManager::new();
        bob.establish_responder(alice_id, &root, bob_initial_priv)
            .expect("bob respond");
        (alice, bob, alice_id, bob_id)
    }

    #[test]
    fn dm_round_trip_basic() {
        let (mut alice, mut bob, alice_id, bob_id) = dm_pair();

        let w = alice.encrypt(&bob_id, b"hi bob", b"").unwrap();
        assert_eq!(bob.decrypt(&alice_id, &w, b"").unwrap(), b"hi bob");

        // Bob can now reply (his send chain was derived during
        // the decrypt above's DH ratchet step).
        let w = bob.encrypt(&alice_id, b"hi alice", b"").unwrap();
        assert_eq!(alice.decrypt(&bob_id, &w, b"").unwrap(), b"hi alice");
    }

    #[test]
    fn dm_back_and_forth_drives_ratchet() {
        let (mut alice, mut bob, alice_id, bob_id) = dm_pair();
        for i in 0..20 {
            let m = format!("a→b #{i}");
            let w = alice.encrypt(&bob_id, m.as_bytes(), b"").unwrap();
            assert_eq!(bob.decrypt(&alice_id, &w, b"").unwrap(), m.as_bytes());

            let m = format!("b→a #{i}");
            let w = bob.encrypt(&alice_id, m.as_bytes(), b"").unwrap();
            assert_eq!(alice.decrypt(&bob_id, &w, b"").unwrap(), m.as_bytes());
        }
    }

    #[test]
    fn no_session_for_peer_errors() {
        let mut alice = SessionManager::new();
        let unknown = IdentityId::from([0xFF; 32]);
        assert!(alice.encrypt(&unknown, b"x", b"").is_err());
        assert!(alice.decrypt(&unknown, b"y", b"").is_err());
    }

    #[test]
    fn duplicate_establish_rejected() {
        let alice_id = IdentityId::from([1u8; 32]);
        let bob_id = IdentityId::from([2u8; 32]);
        let bob_priv = DhStaticSecret::random_from_rng(rand::thread_rng());
        let bob_pub = DhPublicKey::from(&bob_priv);
        let root = shared_root_key();

        let mut alice = SessionManager::new();
        alice
            .establish_initiator(bob_id, &root, bob_pub)
            .expect("first establish");
        // Second establish against the same peer fails — caller
        // must drop_session() first if they really want to reset.
        let bob_pub2 = DhPublicKey::from(&DhStaticSecret::random_from_rng(rand::thread_rng()));
        let result = alice.establish_initiator(bob_id, &root, bob_pub2);
        assert!(result.is_err());

        // Drop and re-establish: now it works.
        assert!(alice.drop_session(&bob_id));
        alice
            .establish_initiator(bob_id, &root, bob_pub2)
            .expect("re-establish after drop");

        // No-op drop on an unknown peer doesn't pretend.
        assert!(!alice.drop_session(&IdentityId::from([0xAA; 32])));
        let _ = alice_id;
    }

    #[test]
    fn aad_binding_is_per_session() {
        // Frames from peer A bound under their AAD must not
        // decrypt under peer B's session — even if the AAD
        // matches, the wire bytes go to the wrong ratchet and
        // both layers' AEAD fail.
        let (mut alice, mut bob, _alice_id, bob_id) = dm_pair();

        // A third party Carol with their own session against Bob.
        let carol_id = IdentityId::from([3u8; 32]);
        let bob_initial_priv = DhStaticSecret::random_from_rng(rand::thread_rng());
        let bob_initial_pub = DhPublicKey::from(&bob_initial_priv);
        let mut carol = SessionManager::new();
        carol
            .establish_initiator(bob_id, &shared_root_key(), bob_initial_pub)
            .unwrap();
        let mut bob_for_carol = SessionManager::new();
        bob_for_carol
            .establish_responder(carol_id, &shared_root_key(), bob_initial_priv)
            .unwrap();

        let w_alice = alice.encrypt(&bob_id, b"from alice", b"meta").unwrap();
        // Carol's session against Bob doesn't decrypt Alice's
        // frame — different DH chains.
        assert!(bob_for_carol
            .decrypt(&carol_id, &w_alice, b"meta")
            .is_err());
        // Bob's actual session against Alice still works.
        assert_eq!(
            bob.decrypt(&_alice_id, &w_alice, b"meta").unwrap(),
            b"from alice"
        );
    }

    #[test]
    fn forward_secrecy_within_chain() {
        // Forward secrecy proxy: re-decrypting a previous wire
        // frame after the chain has advanced fails (the message
        // key is gone — chain has stepped past it).
        let (mut alice, mut bob, alice_id, bob_id) = dm_pair();
        let w0 = alice.encrypt(&bob_id, b"m0", b"").unwrap();
        let w1 = alice.encrypt(&bob_id, b"m1", b"").unwrap();
        assert_eq!(bob.decrypt(&alice_id, &w0, b"").unwrap(), b"m0");
        assert_eq!(bob.decrypt(&alice_id, &w1, b"").unwrap(), b"m1");
        // Replay of either fails — counter monotonicity in the
        // chain ratchet rejects it.
        assert!(bob.decrypt(&alice_id, &w0, b"").is_err());
        assert!(bob.decrypt(&alice_id, &w1, b"").is_err());
    }
}
