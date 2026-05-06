//! Microbenchmarks for the full group-message encrypt/decrypt round
//! trip. Combines:
//!
//! - Plaintext → canonical body bytes
//! - ChaCha20-Poly1305 AEAD encrypt under the group's symmetric key
//! - Hybrid Ed25519 + ML-DSA-44 signature
//! - Wire framing (magic prefix, length prefixes, signature)
//!
//! This is the hot path that runs on every `nativeSendGroupMessage`
//! and (in reverse) on every `decrypt_group_message` callback. The
//! Dilithium signature dominates total cost.
//!
//! Run with `cargo bench --bench group_encrypt_decrypt`. Smoke-only
//! in CI via `cargo bench --no-run`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qubee_crypto::groups::group_manager::{GroupManager, GroupSettings, GroupType};
use qubee_crypto::groups::group_message::{decrypt_group_message, encrypt_group_message};
use qubee_crypto::identity::identity_key::IdentityKeyPair;
use qubee_crypto::storage::secure_keystore::SecureKeystore;

fn bench_encrypt(c: &mut Criterion) {
    let tmp = tempfile::TempDir::new().unwrap();
    let ks_path = tmp.path().join("bench_enc.db");
    let ks = SecureKeystore::new(&ks_path).unwrap();
    let mut gm = GroupManager::new(ks).unwrap();
    let kp = IdentityKeyPair::generate().unwrap();
    let group_id = gm
        .create_group(
            kp.identity_id(),
            kp.public_key(),
            "bench".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    gm.ensure_group_key(group_id).unwrap();

    let plaintext = vec![0xAB_u8; 256];

    c.bench_function("group_encrypt_256b", |b| {
        b.iter(|| {
            let wire = encrypt_group_message(
                black_box(&gm),
                black_box(&kp),
                black_box(group_id),
                black_box(&plaintext),
            )
            .expect("encrypt");
            black_box(wire)
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let tmp = tempfile::TempDir::new().unwrap();
    let ks_path = tmp.path().join("bench_dec.db");
    let ks = SecureKeystore::new(&ks_path).unwrap();
    let mut gm = GroupManager::new(ks).unwrap();
    let kp = IdentityKeyPair::generate().unwrap();
    let group_id = gm
        .create_group(
            kp.identity_id(),
            kp.public_key(),
            "bench".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .unwrap();
    gm.ensure_group_key(group_id).unwrap();

    let plaintext = vec![0xAB_u8; 256];
    let wire = encrypt_group_message(&gm, &kp, group_id, &plaintext).unwrap();

    c.bench_function("group_decrypt_256b", |b| {
        b.iter(|| {
            let decoded = decrypt_group_message(black_box(&gm), black_box(&wire)).expect("decrypt");
            black_box(decoded)
        })
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);
