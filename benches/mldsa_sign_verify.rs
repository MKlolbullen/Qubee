//! Microbenchmarks for the hybrid Ed25519 + ML-DSA-44 signature
//! primitives. Measured paths:
//!
//! - `IdentityKeyPair::sign` — every group message, every handshake
//!   variant, every onboarding bundle.
//! - `IdentityKey::verify_with_max_age` — every receive on every node.
//!
//! Run with `cargo bench --bench mldsa_sign_verify`. Smoke-only in
//! CI via `cargo bench --no-run`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qubee_crypto::identity::identity_key::IdentityKeyPair;

fn bench_sign(c: &mut Criterion) {
    let kp = IdentityKeyPair::generate().expect("identity keypair");
    // 256 bytes ≈ a small group message after canonical encoding.
    // The Dilithium signing cost is dominated by the polynomial
    // arithmetic, not the input length, but pin the input so noise
    // doesn't shift between runs.
    let data = vec![0xA5_u8; 256];

    c.bench_function("hybrid_sign_256b", |b| {
        b.iter(|| {
            let sig = kp.sign(black_box(&data)).expect("sign");
            black_box(sig)
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let kp = IdentityKeyPair::generate().expect("identity keypair");
    let pk = kp.public_key();
    let data = vec![0xA5_u8; 256];
    let sig = kp.sign(&data).expect("sign");

    c.bench_function("hybrid_verify_256b", |b| {
        b.iter(|| {
            // Use a generous max-age so the freshness check doesn't
            // start failing if the bench runs for more than five
            // minutes (the default).
            let ok = pk
                .verify_with_max_age(black_box(&data), black_box(&sig), 86_400)
                .expect("verify");
            black_box(ok)
        })
    });
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
