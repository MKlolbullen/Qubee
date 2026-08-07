#![no_main]
//! Fuzz `IdentityKey::from_bytes` — the one parser that uses bincode
//! directly rather than the 512 KiB-bounded wire decoder. A crafted
//! length prefix must fail cleanly, not drive an allocation (serde's
//! cautious-capacity guard is the safety net; this exercises it hard).
use libfuzzer_sys::fuzz_target;
use qubee_crypto::identity::identity_key::IdentityKey;

fuzz_target!(|data: &[u8]| {
    let _ = IdentityKey::from_bytes(data);
});
