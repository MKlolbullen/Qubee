//! Microbenchmarks for the ML-KEM-768 (Kyber) primitives that gate
//! group key wrapping. Measured paths:
//!
//! - Keypair generation (per-group long-lived key on join + create_group)
//! - Encapsulate (every JoinAccepted, every KeyRotation per remaining
//!   member, every wrapped StateSyncResponse).
//! - Decapsulate (joiner / member receive paths).
//!
//! Run with `cargo bench --bench kyber_kem`. Smoke-only in CI via
//! `cargo bench --no-run`. Baseline numbers live in
//! `docs/perf/baseline.md`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pqcrypto_mlkem::mlkem768::{decapsulate, encapsulate, keypair};

fn bench_keypair(c: &mut Criterion) {
    c.bench_function("kyber768_keypair", |b| {
        b.iter(|| {
            let (pk, sk) = keypair();
            black_box((pk, sk))
        })
    });
}

fn bench_encapsulate(c: &mut Criterion) {
    let (pk, _sk) = keypair();
    c.bench_function("kyber768_encapsulate", |b| {
        b.iter(|| {
            let (ss, ct) = encapsulate(black_box(&pk));
            black_box((ss, ct))
        })
    });
}

fn bench_decapsulate(c: &mut Criterion) {
    let (pk, sk) = keypair();
    let (_ss, ct) = encapsulate(&pk);
    c.bench_function("kyber768_decapsulate", |b| {
        b.iter(|| {
            let ss = decapsulate(black_box(&ct), black_box(&sk));
            black_box(ss)
        })
    });
}

criterion_group!(benches, bench_keypair, bench_encapsulate, bench_decapsulate);
criterion_main!(benches);
