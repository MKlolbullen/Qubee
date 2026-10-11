//! Migration retirement and persistent clock policy at the public pool boundary.
use qubee_crypto::groups::group_handshake::GroupHandshake;
use qubee_crypto::identity::identity_key::IdentityKeyPair;
use qubee_crypto::ratchet::direct::install_peer_bundle;
use qubee_crypto::ratchet::prekey_pool::{fresh_peer, publish};
use qubee_crypto::ratchet::prekey_store::get_or_create_local_bundle;
use qubee_crypto::storage::secure_keystore::SecureKeyStore;
use tempfile::TempDir;

#[test]
fn retired_legacy_material_cannot_regenerate_and_identity_survives_reload() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("lifecycle.db");
    let mut ks = SecureKeyStore::new(&path, b"test-pool-lifecycle").unwrap();
    let signer = IdentityKeyPair::generate().unwrap();
    let first = publish(&mut ks, &signer, 1).unwrap();
    let identity = match GroupHandshake::from_wire(&first).unwrap() {
        GroupHandshake::PrekeyPool { body, .. } => body.identity_x25519,
        _ => panic!("not a pool"),
    };
    let late = 1 + 30 * 24 * 60 * 60 + 61;
    publish(&mut ks, &signer, late).unwrap();
    assert!(get_or_create_local_bundle(&mut ks, late).is_err());
    ks = SecureKeyStore::new(&path, b"test-pool-lifecycle").unwrap();
    let next = publish(&mut ks, &signer, late + 1).unwrap();
    match GroupHandshake::from_wire(&next).unwrap() {
        GroupHandshake::PrekeyPool { body, .. } => assert_eq!(body.identity_x25519, identity),
        _ => panic!("not a pool"),
    }
    assert!(get_or_create_local_bundle(&mut ks, late + 1).is_err());
}

#[test]
fn publication_clock_rollback_and_cached_future_boundary_fail_without_writes() {
    let (local, remote) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let path = local.path().join("local.db");
    let remote_path = remote.path().join("remote.db");
    let mut ks = SecureKeyStore::new(&path, b"clock-local").unwrap();
    let mut peer = SecureKeyStore::new(&remote_path, b"clock-remote").unwrap();
    let signer = IdentityKeyPair::generate().unwrap();
    let wire = publish(&mut ks, &signer, 100).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(publish(&mut ks, &signer, 39).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    publish(&mut ks, &signer, 40).unwrap(); // Exact allowed 60-second rollback.
    install_peer_bundle(&mut peer, &wire).unwrap();
    let before = std::fs::read(&remote_path).unwrap();
    assert!(fresh_peer(&mut peer, &signer.identity_id(), 39).is_err());
    assert!(fresh_peer(&mut peer, &signer.identity_id(), 40)
        .unwrap()
        .is_some());
    assert_eq!(std::fs::read(&remote_path).unwrap(), before);
}
