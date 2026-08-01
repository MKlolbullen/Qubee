//! 1:1 ratchet sessions (Ratchet Stage 3b).
//!
//! A [`Session`] is one forward-secret, deniable, post-quantum
//! conversation with a single peer. It ties the three Stage 1/2 pieces
//! together:
//!
//! * [`super::pqxdh`] establishes the initial 32-byte shared secret from
//!   a peer's prekey bundle (deniable X25519 DHs + an ML-KEM-768
//!   encapsulation).
//! * [`super::double_ratchet::DoubleRatchet`] provides per-message
//!   forward secrecy + post-compromise security on top of that secret.
//! * [`super::prekey_store`] supplies the local device's long-lived
//!   bundle secret and the cached, signature-verified peer bundles.
//!
//! Sessions are keyed by the peer's [`IdentityId`] and persist to the
//! encrypted keystore, so a conversation survives an app restart without
//! ever reusing a message key.
//!
//! This stage does **not** yet touch the JNI bridge or the wire format —
//! it is a self-contained, exhaustively-tested Rust layer. Serialising
//! the PQXDH [`InitialMessage`] onto the wire and routing live 1:1
//! traffic through sessions are the following stages (3c/3d).

use anyhow::{anyhow, Result};

use crate::identity::identity_key::IdentityId;
use crate::ratchet::double_ratchet::{DoubleRatchet, MessageHeader};
use crate::ratchet::pqxdh::{
    initiate, respond, InitialMessage, PrekeyBundlePublic, PrekeyBundleSecret,
};
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

const SESSION_AD_TAG: &[u8] = b"qubee_session_ad_v1";

pub(crate) fn session_key_id(peer: &IdentityId) -> String {
    format!("ratchet_session_{}", hex::encode(peer.as_ref()))
}

/// Deterministic per-conversation associated data, identical on both
/// sides regardless of who initiated. Bound into every message's AEAD so
/// a frame can never be replayed into a different pair's conversation.
fn conversation_ad(a: &IdentityId, b: &IdentityId) -> [u8; 32] {
    let (lo, hi): (&[u8], &[u8]) = if a.as_ref() <= b.as_ref() {
        (a.as_ref(), b.as_ref())
    } else {
        (b.as_ref(), a.as_ref())
    };
    let mut h = blake3::Hasher::new();
    h.update(SESSION_AD_TAG);
    h.update(lo);
    h.update(hi);
    *h.finalize().as_bytes()
}

/// On-disk form of a session: the peer id, the conversation AD, and the
/// serialised ratchet state. Contains live key material — keystore only,
/// never the wire.
#[derive(Serialize, Deserialize)]
struct StoredSession {
    peer_id: IdentityId,
    conversation_ad: [u8; 32],
    ratchet: Vec<u8>,
}

/// One 1:1 ratchet conversation.
///
/// Not `Clone` — it owns a [`DoubleRatchet`], and duplicating ratchet
/// state would reuse message keys. Persist + reload instead.
pub struct Session {
    peer_id: IdentityId,
    conversation_ad: [u8; 32],
    ratchet: DoubleRatchet,
}

impl Session {
    /// Establish a session as the **initiator** against a peer's verified
    /// prekey bundle. Returns the session plus the PQXDH
    /// [`InitialMessage`] the caller must deliver to the peer in (or
    /// alongside) the first message so they can complete the handshake.
    ///
    /// `local_secret` is this device's own bundle secret (from
    /// [`super::prekey_store::get_or_create_local_bundle`]); its
    /// `identity` X25519 key is used as the deniable initiator identity.
    pub fn establish_initiator(
        local_id: IdentityId,
        peer_id: IdentityId,
        local_secret: &PrekeyBundleSecret,
        peer_public: &PrekeyBundlePublic,
    ) -> Result<(Self, InitialMessage)> {
        let result = initiate(&local_secret.identity, peer_public)?;
        let ratchet = DoubleRatchet::init_alice(result.shared_secret, result.bob_ratchet_public)?;
        let session = Session {
            peer_id,
            conversation_ad: conversation_ad(&local_id, &peer_id),
            ratchet,
        };
        Ok((session, result.initial_message))
    }

    /// Establish a session as the **responder** from an inbound PQXDH
    /// [`InitialMessage`], using this device's own bundle secret to
    /// reproduce the shared secret.
    pub fn establish_responder(
        local_id: IdentityId,
        peer_id: IdentityId,
        local_secret: &PrekeyBundleSecret,
        initial: &InitialMessage,
    ) -> Result<Self> {
        let (sk, ratchet_secret) = respond(local_secret, initial)?;
        let ratchet = DoubleRatchet::init_bob(sk, ratchet_secret);
        Ok(Session {
            peer_id,
            conversation_ad: conversation_ad(&local_id, &peer_id),
            ratchet,
        })
    }

    /// The peer this session talks to.
    pub fn peer_id(&self) -> IdentityId {
        self.peer_id
    }

    /// Encrypt a plaintext for the peer. The conversation AD is bound
    /// automatically. Returns the ratchet header (sent in the clear) and
    /// the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>)> {
        self.ratchet.encrypt(plaintext, &self.conversation_ad)
    }

    /// Decrypt a peer message given its header + ciphertext.
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.ratchet
            .decrypt(header, ciphertext, &self.conversation_ad)
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let stored = StoredSession {
            peer_id: self.peer_id,
            conversation_ad: self.conversation_ad,
            ratchet: self.ratchet.serialize_state()?,
        };
        bincode::serialize(&stored).map_err(|e| anyhow!("serialize session: {e}"))
    }

    fn deserialize(bytes: &[u8]) -> Result<Self> {
        let stored: StoredSession =
            bincode::deserialize(bytes).map_err(|e| anyhow!("deserialize session: {e}"))?;
        Ok(Session {
            peer_id: stored.peer_id,
            conversation_ad: stored.conversation_ad,
            ratchet: DoubleRatchet::deserialize_state(&stored.ratchet)?,
        })
    }
}

fn session_metadata() -> KeyMetadata {
    KeyMetadata {
        algorithm: "double-ratchet-session".to_string(),
        key_size: 32,
        usage: vec![KeyUsage::Encryption],
        expiry: None,
        tags: std::collections::HashMap::new(),
    }
}

/// Persist a session to the encrypted keystore, keyed by its peer id.
/// Overwrites any prior state for that peer — always store the latest
/// state after an encrypt/decrypt so no message key is ever reused.
pub fn store_session(ks: &mut SecureKeyStore, session: &Session) -> Result<()> {
    let bytes = session.serialize()?;
    ks.store_key(
        &session_key_id(&session.peer_id),
        &bytes,
        KeyType::RootKey,
        session_metadata(),
    )
}

/// Load a peer's session from the keystore, if one exists.
pub fn load_session(ks: &mut SecureKeyStore, peer: &IdentityId) -> Result<Option<Session>> {
    match ks.retrieve_key(&session_key_id(peer))? {
        Some(secret) => Ok(Some(Session::deserialize(secret.expose_secret())?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::pqxdh::generate_bundle;
    use tempfile::TempDir;

    fn fresh_ks() -> (SecureKeyStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let ks = SecureKeyStore::new(path, b"test-session-passphrase").unwrap();
        (ks, dir)
    }

    fn ids() -> (IdentityId, IdentityId) {
        (IdentityId::from([1u8; 32]), IdentityId::from([2u8; 32]))
    }

    /// Establish a live Alice→Bob session pair via PQXDH.
    fn establish_pair(alice_id: IdentityId, bob_id: IdentityId) -> (Session, Session) {
        let (bob_secret, bob_kem_pub) = generate_bundle().unwrap();
        let bob_public = bob_secret.public_with_kem(bob_kem_pub);
        let (alice_secret, _alice_kem_pub) = generate_bundle().unwrap();

        let (alice, initial) =
            Session::establish_initiator(alice_id, bob_id, &alice_secret, &bob_public).unwrap();
        let bob = Session::establish_responder(bob_id, alice_id, &bob_secret, &initial).unwrap();
        (alice, bob)
    }

    #[test]
    fn established_session_exchanges_both_ways() {
        let (alice_id, bob_id) = ids();
        let (mut alice, mut bob) = establish_pair(alice_id, bob_id);

        let (h, c) = alice.encrypt(b"hello from the initiator").unwrap();
        assert_eq!(bob.decrypt(&h, &c).unwrap(), b"hello from the initiator");
        let (h2, c2) = bob.encrypt(b"hello back").unwrap();
        assert_eq!(alice.decrypt(&h2, &c2).unwrap(), b"hello back");
        assert_eq!(alice.peer_id(), bob_id);
        assert_eq!(bob.peer_id(), alice_id);
    }

    #[test]
    fn conversation_ad_is_symmetric_and_binds_the_pair() {
        let (a, b) = ids();
        assert_eq!(conversation_ad(&a, &b), conversation_ad(&b, &a));
        let c = IdentityId::from([3u8; 32]);
        assert_ne!(conversation_ad(&a, &b), conversation_ad(&a, &c));
    }

    #[test]
    fn session_persists_and_resumes_across_reload() {
        let (alice_id, bob_id) = ids();
        let (mut alice, mut bob) = establish_pair(alice_id, bob_id);
        let (mut ks, _d) = fresh_ks();

        // One exchange, then persist Alice mid-conversation.
        let (h, c) = alice.encrypt(b"before restart").unwrap();
        assert_eq!(bob.decrypt(&h, &c).unwrap(), b"before restart");
        store_session(&mut ks, &alice).unwrap();
        drop(alice);

        // Reload Alice from the keystore and keep going — no key reuse.
        let mut alice = load_session(&mut ks, &bob_id).unwrap().unwrap();
        assert_eq!(alice.peer_id(), bob_id);
        let (h2, c2) = alice.encrypt(b"after restart").unwrap();
        assert_eq!(bob.decrypt(&h2, &c2).unwrap(), b"after restart");
    }

    #[test]
    fn missing_session_loads_as_none() {
        let (mut ks, _d) = fresh_ks();
        let (_, bob_id) = ids();
        assert!(load_session(&mut ks, &bob_id).unwrap().is_none());
    }

    #[test]
    fn wrong_conversation_cannot_decrypt() {
        // A frame from the Alice/Bob session must not open under a session
        // bound to a different pair (different conversation AD).
        let (alice_id, bob_id) = ids();
        let (mut alice, _bob) = establish_pair(alice_id, bob_id);
        let carol_id = IdentityId::from([9u8; 32]);
        let (_alice2, mut carol) = establish_pair(alice_id, carol_id);

        let (h, c) = alice.encrypt(b"for bob only").unwrap();
        assert!(
            carol.decrypt(&h, &c).is_err(),
            "cross-conversation decrypt must fail",
        );
    }
}
