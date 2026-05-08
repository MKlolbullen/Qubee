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
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};
use secrecy::ExposeSecret;
use std::collections::HashMap as StdHashMap;

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

    // -- Persistence --------------------------------------------------------
    //
    // The active flow on Android: GroupManager owns the keystore;
    // SessionManager doesn't have its own copy. Callers (typically
    // the JNI bridge) hand a `&mut SecureKeyStore` to the
    // *_persistent variants, which encrypt+decrypt the underlying
    // ratchet state so it survives a process restart.
    //
    // Wiring lives at the SessionManager layer (rather than inside
    // DoubleRatchet) so the keystore stays a single dependency at
    // the embedder boundary — no circular module reference between
    // crypto/ and storage/.

    /// Encrypt `plaintext` to `peer_id` and persist the advanced
    /// ratchet state to the encrypted keystore. Atomic from the
    /// caller's perspective: AEAD failure leaves both the in-memory
    /// session and the keystore unchanged (DoubleRatchet's
    /// snapshot/commit pattern handles the in-memory side; we only
    /// touch the keystore on success).
    pub fn encrypt_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: &IdentityId,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| anyhow!("no DM session for peer"))?;
        let wire = session.encrypt(plaintext, aad)?;
        Self::persist_session_to_keystore(keystore, peer_id, &session.ratchet)?;
        Ok(wire)
    }

    /// Decrypt a frame from `peer_id` and persist the advanced
    /// ratchet state. Same atomicity as `encrypt_persistent`.
    pub fn decrypt_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: &IdentityId,
        wire: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get_mut(peer_id)
            .ok_or_else(|| anyhow!("no DM session for peer"))?;
        let pt = session.decrypt(wire, aad)?;
        Self::persist_session_to_keystore(keystore, peer_id, &session.ratchet)?;
        Ok(pt)
    }

    /// Open an initiator-side session and persist the freshly
    /// constructed state. Errors if a session for that peer is
    /// already either in memory OR persisted on disk under the
    /// same key — callers must `drop_session_persistent` first to
    /// re-handshake.
    pub fn establish_initiator_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        peer_initial_dh_pub: DhPublicKey,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id)
            || keystore.list_keys().iter().any(|k| k == &session_key_id(&peer_id))
        {
            return Err(anyhow!(
                "session for peer already exists (memory or keystore); drop it first"
            ));
        }
        let session = DmSession::establish_initiator(peer_id, root_key, peer_initial_dh_pub)?;
        Self::persist_session_to_keystore(keystore, &peer_id, &session.ratchet)?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Initiator-side, hybrid mode, persistent.
    pub fn establish_initiator_hybrid_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        peer_initial_dh_pub: DhPublicKey,
        kyber: KyberConfig,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id)
            || keystore.list_keys().iter().any(|k| k == &session_key_id(&peer_id))
        {
            return Err(anyhow!(
                "session for peer already exists (memory or keystore); drop it first"
            ));
        }
        let session =
            DmSession::establish_initiator_hybrid(peer_id, root_key, peer_initial_dh_pub, kyber)?;
        Self::persist_session_to_keystore(keystore, &peer_id, &session.ratchet)?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Open a responder-side session and persist it.
    pub fn establish_responder_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        own_initial_keypair: DhStaticSecret,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id)
            || keystore.list_keys().iter().any(|k| k == &session_key_id(&peer_id))
        {
            return Err(anyhow!(
                "session for peer already exists (memory or keystore); drop it first"
            ));
        }
        let session = DmSession::establish_responder(peer_id, root_key, own_initial_keypair)?;
        Self::persist_session_to_keystore(keystore, &peer_id, &session.ratchet)?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Responder-side, hybrid mode, persistent.
    pub fn establish_responder_hybrid_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: IdentityId,
        root_key: &[u8; 32],
        own_initial_keypair: DhStaticSecret,
        kyber: KyberConfig,
    ) -> Result<()> {
        if self.sessions.contains_key(&peer_id)
            || keystore.list_keys().iter().any(|k| k == &session_key_id(&peer_id))
        {
            return Err(anyhow!(
                "session for peer already exists (memory or keystore); drop it first"
            ));
        }
        let session =
            DmSession::establish_responder_hybrid(peer_id, root_key, own_initial_keypair, kyber)?;
        Self::persist_session_to_keystore(keystore, &peer_id, &session.ratchet)?;
        self.sessions.insert(peer_id, session);
        Ok(())
    }

    /// Drop a session from memory AND from the keystore. Returns
    /// `true` if anything was deleted in either place.
    pub fn drop_session_persistent(
        &mut self,
        keystore: &mut SecureKeyStore,
        peer_id: &IdentityId,
    ) -> Result<bool> {
        let in_memory = self.sessions.remove(peer_id).is_some();
        let on_disk = keystore.delete_key(&session_key_id(peer_id))?;
        Ok(in_memory || on_disk)
    }

    /// Restore every persisted DM session from the keystore.
    /// Skips entries that fail to deserialise (corruption, format
    /// mismatch) with a tracing warning rather than failing the
    /// whole load — the rest of the manager is still useful.
    /// Idempotent: safe to call on an already-loaded manager.
    pub fn load_from_keystore(&mut self, keystore: &mut SecureKeyStore) -> Result<usize> {
        let session_keys: Vec<String> = keystore
            .list_keys()
            .into_iter()
            .filter(|k| k.starts_with(SESSION_KEY_PREFIX))
            .collect();

        let mut loaded = 0usize;
        for key_id in session_keys {
            let peer_id = match parse_session_key_id(&key_id) {
                Some(p) => p,
                None => continue,
            };
            let bytes = match keystore.retrieve_key(&key_id)? {
                Some(b) => b,
                None => continue,
            };
            let ratchet = match DoubleRatchet::restore(bytes.expose_secret()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        "skipping unrestorable DM session {peer_id:?}: {e}"
                    );
                    continue;
                }
            };
            self.sessions
                .insert(peer_id, DmSession { peer_id, ratchet });
            loaded += 1;
        }
        Ok(loaded)
    }

    fn persist_session_to_keystore(
        keystore: &mut SecureKeyStore,
        peer_id: &IdentityId,
        ratchet: &DoubleRatchet,
    ) -> Result<()> {
        let bytes = ratchet.persist()?;
        let metadata = KeyMetadata {
            algorithm: "qubee_dm_session_v1".to_string(),
            key_size: bytes.len(),
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: StdHashMap::new(),
        };
        keystore.store_key(&session_key_id(peer_id), &bytes, KeyType::ChainKey, metadata)
    }
}

/// Keystore key prefix for persisted DM sessions.
const SESSION_KEY_PREFIX: &str = "dm_session_";

fn session_key_id(peer_id: &IdentityId) -> String {
    format!("{SESSION_KEY_PREFIX}{}", hex::encode(peer_id.as_ref()))
}

/// Inverse of [`session_key_id`]. Returns `None` if the key
/// doesn't match the expected `dm_session_<hex>` shape.
fn parse_session_key_id(key_id: &str) -> Option<IdentityId> {
    let rest = key_id.strip_prefix(SESSION_KEY_PREFIX)?;
    if rest.len() != 64 {
        return None;
    }
    let bytes = hex::decode(rest).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(IdentityId::from(arr))
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
    fn keystore_persist_round_trip() {
        use crate::storage::secure_keystore::{install_test_password, SecureKeyStore};
        install_test_password();
        let tmp = tempfile::TempDir::new().unwrap();
        let alice_ks_path = tmp.path().join("alice_ks.db");
        let bob_ks_path = tmp.path().join("bob_ks.db");

        let alice_id = IdentityId::from([1u8; 32]);
        let bob_id = IdentityId::from([2u8; 32]);
        let bob_priv = DhStaticSecret::random_from_rng(rand::thread_rng());
        let bob_pub = DhPublicKey::from(&bob_priv);
        let root = shared_root_key();

        // Pre-restart: open both keystores, establish sessions,
        // round-trip a few messages so chain state is non-trivial.
        let alice_first_wire = {
            let mut alice_ks = SecureKeyStore::new(&alice_ks_path).unwrap();
            let mut bob_ks = SecureKeyStore::new(&bob_ks_path).unwrap();

            let mut alice = SessionManager::new();
            alice
                .establish_initiator_persistent(&mut alice_ks, bob_id, &root, bob_pub)
                .unwrap();
            let mut bob = SessionManager::new();
            bob.establish_responder_persistent(
                &mut bob_ks,
                alice_id,
                &root,
                DhStaticSecret::from(bob_priv.to_bytes()),
            )
            .unwrap();

            for i in 0..3 {
                let m = format!("a{i}");
                let w = alice
                    .encrypt_persistent(&mut alice_ks, &bob_id, m.as_bytes(), b"")
                    .unwrap();
                assert_eq!(
                    bob.decrypt_persistent(&mut bob_ks, &alice_id, &w, b"").unwrap(),
                    m.as_bytes()
                );
                let m = format!("b{i}");
                let w = bob
                    .encrypt_persistent(&mut bob_ks, &alice_id, m.as_bytes(), b"")
                    .unwrap();
                assert_eq!(
                    alice.decrypt_persistent(&mut alice_ks, &bob_id, &w, b"").unwrap(),
                    m.as_bytes()
                );
            }

            // One more outgoing from alice, persisted, captured.
            alice
                .encrypt_persistent(&mut alice_ks, &bob_id, b"pre-restart", b"")
                .unwrap()
            // alice/bob/keystores drop here, flushing to disk.
        };

        // Post-restart: reopen both keystores, restore sessions.
        let mut alice_ks = SecureKeyStore::new(&alice_ks_path).unwrap();
        let mut bob_ks = SecureKeyStore::new(&bob_ks_path).unwrap();
        let mut alice = SessionManager::new();
        let mut bob = SessionManager::new();
        let alice_loaded = alice.load_from_keystore(&mut alice_ks).unwrap();
        let bob_loaded = bob.load_from_keystore(&mut bob_ks).unwrap();
        assert_eq!(alice_loaded, 1);
        assert_eq!(bob_loaded, 1);

        // The pre-restart wire frame still decrypts (bob's chain
        // state was persisted in lockstep with alice's; restoring
        // both lands them on aligned counters).
        assert_eq!(
            bob.decrypt_persistent(&mut bob_ks, &alice_id, &alice_first_wire, b"")
                .unwrap(),
            b"pre-restart"
        );

        // Continue the conversation across the restart boundary.
        let w = alice
            .encrypt_persistent(&mut alice_ks, &bob_id, b"after-restart", b"")
            .unwrap();
        assert_eq!(
            bob.decrypt_persistent(&mut bob_ks, &alice_id, &w, b"")
                .unwrap(),
            b"after-restart"
        );
        let w = bob
            .encrypt_persistent(&mut bob_ks, &alice_id, b"after-restart-reply", b"")
            .unwrap();
        assert_eq!(
            alice.decrypt_persistent(&mut alice_ks, &bob_id, &w, b"")
                .unwrap(),
            b"after-restart-reply"
        );
    }

    #[test]
    fn keystore_drop_session_clears_disk() {
        use crate::storage::secure_keystore::{install_test_password, SecureKeyStore};
        install_test_password();
        let tmp = tempfile::TempDir::new().unwrap();
        let ks_path = tmp.path().join("ks.db");
        let mut ks = SecureKeyStore::new(&ks_path).unwrap();
        let bob_id = IdentityId::from([2u8; 32]);
        let bob_priv = DhStaticSecret::random_from_rng(rand::thread_rng());
        let bob_pub = DhPublicKey::from(&bob_priv);
        let root = shared_root_key();

        let mut mgr = SessionManager::new();
        mgr.establish_initiator_persistent(&mut ks, bob_id, &root, bob_pub)
            .unwrap();
        let session_key = format!(
            "{SESSION_KEY_PREFIX}{}",
            hex::encode(bob_id.as_ref())
        );
        assert!(ks.list_keys().iter().any(|k| k == &session_key));

        let dropped = mgr.drop_session_persistent(&mut ks, &bob_id).unwrap();
        assert!(dropped);
        assert!(!ks.list_keys().iter().any(|k| k == &session_key));

        // Re-establish after drop now succeeds (no in-memory or
        // on-disk collision).
        mgr.establish_initiator_persistent(&mut ks, bob_id, &root, bob_pub)
            .unwrap();
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
