// `secure_keystore` lives under `crate::storage::secure_keystore`.
// The previous duplicate copy here triggered an E0119 (conflicting
// Drop impls for `SecureKeyStore`); single source of truth wins.
pub mod secure_rng;

// Page-locked buffers via libc mlock/munlock. Behind the `legacy`
// feature: it depends on the old `secrecy::Secret` type and pulls in
// platform-specific unsafe blocks the modern modules don't need.
#[cfg(feature = "legacy")]
pub mod secure_memory;
