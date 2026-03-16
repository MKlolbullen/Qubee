# Audit Remediation Pass 4

This pass moves the live application path closer to a functional post-quantum deployment.

## What changed

- JNI now exposes explicit hybrid session bootstrap entry points:
  - `nativeCreateHybridSessionInit(...)`
  - `nativeAcceptHybridSessionInit(...)`
- Android now prefers the hybrid bootstrap path when native crypto is available.
- Session state now carries:
  - bootstrap payloads
  - negotiated/declared algorithm metadata
- The repository publishes a hybrid session bootstrap control envelope before the first encrypted message on a native-backed session.
- The receiver accepts the hybrid bootstrap control envelope and persists the resulting native session before processing encrypted traffic.
- Native relay challenge signing now uses post-quantum Dilithium instead of Ed25519.
- Native session bundle metadata now uses ML-KEM terminology in the advertised algorithm string.
- Added a native test that checks PQ relay signature generation and verification.

## Security impact

This pass improves the real app path in two important ways:

1. The Android caller no longer defaults to the legacy classical-only session bootstrap when native crypto is present.
2. Relay authentication signatures in the native contract are no longer classical-only.

## Remaining gaps

- The implementation still uses the `pqcrypto_kyber` / `pqcrypto_dilithium` crate ecosystem rather than a FIPS-validated ML-KEM / ML-DSA implementation.
- The shell fallback path remains non-PQ and should not be treated as equivalent to the native path.
- Relay TLS and stronger transport hardening are still outstanding.
- This pass was not compiled in-session because no Rust or Android toolchain is available in the execution environment.
