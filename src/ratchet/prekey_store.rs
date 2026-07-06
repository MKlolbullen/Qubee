//! Prekey bundle persistence + conversion (Ratchet Stage 2).
//!
//! Bridges three representations of a prekey bundle:
//!
//! * [`super::pqxdh::PrekeyBundleSecret`] — the live X25519 / ML-KEM
//!   secret material used by the PQXDH handshake.
//! * [`crate::groups::group_handshake::PrekeyBundleBody`] — the
//!   signed, publishable *public* wire frame.
//! * A serialised on-disk form persisted in the encrypted
//!   [`SecureKeyStore`].
//!
//! It also caches *verified peer* bundles so a later session-setup
//! stage can fetch a contact's bundle and run [`super::pqxdh::initiate`]
//! against it. Nothing here consumes a bundle for send/receive yet —
//! that is Stage 3.

use anyhow::{anyhow, Result};
use pqcrypto_mlkem::mlkem768::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::groups::group_handshake::PrekeyBundleBody;
use crate::identity::identity_key::{IdentityId, IdentityKey};
use crate::ratchet::pqxdh::{PrekeyBundlePublic, PrekeyBundleSecret};
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};

/// Keystore id under which the local device's secret bundle is stored.
const LOCAL_BUNDLE_KEY_ID: &str = "ratchet_local_prekey_bundle_v1";

fn peer_key_id(id: &IdentityId) -> String {
    format!("ratchet_peer_prekey_{}", hex::encode(id.as_ref() as &[u8]))
}

/// On-disk serialisation of a secret prekey bundle. The KEM secret
/// can't reproduce its public, so we persist the public alongside it.
#[derive(Serialize, Deserialize)]
struct StoredLocalBundle {
    identity: [u8; 32],
    signed_prekey: [u8; 32],
    one_time_prekey: Option<[u8; 32]>,
    kem_secret: Vec<u8>,
    kem_public: Vec<u8>,
    created_at: u64,
}

fn bundle_metadata() -> KeyMetadata {
    KeyMetadata {
        algorithm: "x25519+mlkem768-prekey".to_string(),
        key_size: 32,
        usage: vec![KeyUsage::KeyAgreement],
        expiry: None,
        tags: std::collections::HashMap::new(),
    }
}

/// Load the local secret bundle from the keystore, or generate + persist
/// a fresh one on first call. Returns the secret bundle plus its KEM
/// public (needed to build the publishable body).
pub fn get_or_create_local_bundle(
    ks: &mut SecureKeyStore,
    now: u64,
) -> Result<(PrekeyBundleSecret, KemPublicKey)> {
    if let Some(secret) = ks.retrieve_key(LOCAL_BUNDLE_KEY_ID)? {
        let stored: StoredLocalBundle = bincode::deserialize(secret.expose_secret())
            .map_err(|e| anyhow!("decode stored prekey bundle: {e}"))?;
        return stored_to_secret(stored);
    }

    // First run: generate + persist.
    let (secret, kem_public) = super::pqxdh::generate_bundle()?;
    let stored = StoredLocalBundle {
        identity: secret.identity.to_bytes(),
        signed_prekey: secret.signed_prekey.to_bytes(),
        one_time_prekey: secret.one_time_prekey.as_ref().map(|s| s.to_bytes()),
        kem_secret: secret.kem_secret.as_bytes().to_vec(),
        kem_public: kem_public.as_bytes().to_vec(),
        created_at: now,
    };
    let bytes = bincode::serialize(&stored).map_err(|e| anyhow!("encode prekey bundle: {e}"))?;
    ks.store_key(
        LOCAL_BUNDLE_KEY_ID,
        &bytes,
        KeyType::PreKey,
        bundle_metadata(),
    )?;
    Ok((secret, kem_public))
}

fn stored_to_secret(stored: StoredLocalBundle) -> Result<(PrekeyBundleSecret, KemPublicKey)> {
    let kem_secret = KemSecretKey::from_bytes(&stored.kem_secret)
        .map_err(|e| anyhow!("invalid stored KEM secret: {e}"))?;
    let kem_public = KemPublicKey::from_bytes(&stored.kem_public)
        .map_err(|e| anyhow!("invalid stored KEM public: {e}"))?;
    let secret = PrekeyBundleSecret {
        identity: StaticSecret::from(stored.identity),
        signed_prekey: StaticSecret::from(stored.signed_prekey),
        one_time_prekey: stored.one_time_prekey.map(StaticSecret::from),
        kem_secret,
    };
    Ok((secret, kem_public))
}

/// Build the publishable (unsigned) [`PrekeyBundleBody`] from a secret
/// bundle, its KEM public, and the publisher's identity. The caller
/// signs it with `group_handshake::sign_prekey_bundle`.
pub fn build_body(
    secret: &PrekeyBundleSecret,
    kem_public: &KemPublicKey,
    publisher: IdentityKey,
    timestamp: u64,
) -> PrekeyBundleBody {
    PrekeyBundleBody {
        publisher,
        identity_x25519: *PublicKey::from(&secret.identity).as_bytes(),
        signed_prekey: *PublicKey::from(&secret.signed_prekey).as_bytes(),
        one_time_prekey: secret
            .one_time_prekey
            .as_ref()
            .map(|s| *PublicKey::from(s).as_bytes()),
        kem_public: kem_public.as_bytes().to_vec(),
        timestamp,
    }
}

/// Convert a received public bundle body into the PQXDH-facing
/// [`PrekeyBundlePublic`] so it can drive `pqxdh::initiate`.
pub fn body_to_public(body: &PrekeyBundleBody) -> Result<PrekeyBundlePublic> {
    let kem_public = KemPublicKey::from_bytes(&body.kem_public)
        .map_err(|e| anyhow!("invalid bundle KEM public: {e}"))?;
    Ok(PrekeyBundlePublic {
        identity: PublicKey::from(body.identity_x25519),
        signed_prekey: PublicKey::from(body.signed_prekey),
        one_time_prekey: body.one_time_prekey.map(PublicKey::from),
        kem_public,
    })
}

/// Cache a *verified* peer bundle keyed by the publisher's IdentityId.
/// The caller must have already checked the signature
/// (`verify_prekey_bundle`) — this only persists.
pub fn store_peer_bundle(ks: &mut SecureKeyStore, body: &PrekeyBundleBody) -> Result<()> {
    let id = body.publisher.identity_id;
    let bytes = bincode::serialize(body).map_err(|e| anyhow!("encode peer bundle: {e}"))?;
    ks.store_key(
        &peer_key_id(&id),
        &bytes,
        KeyType::PreKey,
        bundle_metadata(),
    )
}

/// Fetch a cached peer bundle, if present.
pub fn get_peer_bundle(
    ks: &mut SecureKeyStore,
    id: &IdentityId,
) -> Result<Option<PrekeyBundleBody>> {
    match ks.retrieve_key(&peer_key_id(id))? {
        Some(secret) => {
            let body: PrekeyBundleBody = bincode::deserialize(secret.expose_secret())
                .map_err(|e| anyhow!("decode peer bundle: {e}"))?;
            Ok(Some(body))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::group_handshake::{
        sign_prekey_bundle, verify_prekey_bundle, GroupHandshake,
    };
    use crate::identity::identity_key::IdentityKeyPair;
    use crate::ratchet::double_ratchet::DoubleRatchet;
    use crate::ratchet::pqxdh::{initiate, respond};
    use tempfile::TempDir;

    fn fresh_ks() -> (SecureKeyStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ks.db");
        let ks = SecureKeyStore::new(path, b"test-prekey-passphrase").unwrap();
        (ks, dir)
    }

    #[test]
    fn local_bundle_persists_and_reloads() {
        let (mut ks, _d) = fresh_ks();
        let (s1, k1) = get_or_create_local_bundle(&mut ks, 1000).unwrap();
        let (s2, k2) = get_or_create_local_bundle(&mut ks, 2000).unwrap();
        // Same identity public across reloads (i.e. it loaded, not regenerated).
        assert_eq!(
            PublicKey::from(&s1.identity).as_bytes(),
            PublicKey::from(&s2.identity).as_bytes(),
        );
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn sign_verify_round_trip_and_tamper() {
        let (mut ks, _d) = fresh_ks();
        let kp = IdentityKeyPair::generate().unwrap();
        let (secret, kem_pub) = get_or_create_local_bundle(&mut ks, 42).unwrap();
        let body = build_body(&secret, &kem_pub, kp.public_key(), 42);

        let signed = sign_prekey_bundle(&kp, body.clone()).unwrap();
        let (signed_body, sig) = match signed {
            GroupHandshake::PrekeyBundle { body, signature } => (body, signature),
            _ => unreachable!(),
        };
        assert!(verify_prekey_bundle(&signed_body, &sig).unwrap());

        // Tampered signed_prekey must fail verification.
        let mut bad = signed_body.clone();
        bad.signed_prekey[0] ^= 0x01;
        assert!(!verify_prekey_bundle(&bad, &sig).unwrap());

        // A different signer can't have produced it.
        let other = IdentityKeyPair::generate().unwrap();
        let mut wrong_pub = signed_body.clone();
        wrong_pub.publisher = other.public_key();
        assert!(!verify_prekey_bundle(&wrong_pub, &sig).unwrap());
    }

    #[test]
    fn peer_bundle_cache_round_trips() {
        let (mut ks, _d) = fresh_ks();
        let kp = IdentityKeyPair::generate().unwrap();
        let (secret, kem_pub) = get_or_create_local_bundle(&mut ks, 7).unwrap();
        let body = build_body(&secret, &kem_pub, kp.public_key(), 7);

        assert!(get_peer_bundle(&mut ks, &kp.identity_id())
            .unwrap()
            .is_none());
        store_peer_bundle(&mut ks, &body).unwrap();
        let got = get_peer_bundle(&mut ks, &kp.identity_id())
            .unwrap()
            .unwrap();
        assert_eq!(got.identity_x25519, body.identity_x25519);
        assert_eq!(got.kem_public, body.kem_public);
    }

    #[test]
    fn cached_bundle_drives_a_real_pqxdh_handshake() {
        // Bob generates + persists a bundle; Alice fetches the public
        // body from the cache and completes PQXDH → ratchet.
        let (mut bob_ks, _bd) = fresh_ks();
        let bob_kp = IdentityKeyPair::generate().unwrap();
        let (bob_secret, bob_kem_pub) = get_or_create_local_bundle(&mut bob_ks, 1).unwrap();
        let bob_body = build_body(&bob_secret, &bob_kem_pub, bob_kp.public_key(), 1);

        // Alice caches Bob's (verified) bundle, then converts + initiates.
        let (mut alice_ks, _ad) = fresh_ks();
        store_peer_bundle(&mut alice_ks, &bob_body).unwrap();
        let cached = get_peer_bundle(&mut alice_ks, &bob_kp.identity_id())
            .unwrap()
            .unwrap();
        let bob_public = body_to_public(&cached).unwrap();

        let alice_identity = StaticSecret::from([9u8; 32]);
        let init = initiate(&alice_identity, &bob_public).unwrap();
        let (bob_sk, bob_ratchet_secret) = respond(&bob_secret, &init.initial_message).unwrap();

        let mut alice =
            DoubleRatchet::init_alice(init.shared_secret, init.bob_ratchet_public).unwrap();
        let mut bob = DoubleRatchet::init_bob(bob_sk, bob_ratchet_secret);
        let (h, c) = alice.encrypt(b"cached-bundle handshake", b"cid").unwrap();
        assert_eq!(
            bob.decrypt(&h, &c, b"cid").unwrap(),
            b"cached-bundle handshake"
        );
    }
}
