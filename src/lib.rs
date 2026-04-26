// Modules that survived the round-9 audit and `cargo check` clean.
pub mod errors;
pub mod logging;
pub mod config;
pub mod ephemeral_keys;
pub mod identity;
pub mod groups;
pub mod onboarding;
pub mod network;
pub mod storage;
pub mod security;

// Legacy modules from the early prototype. They lean on dependency
// versions and APIs that no longer match Cargo.toml; some reference
// crates that aren't even declared (e.g. `double_ratchet`). Gated
// behind the `legacy` feature so default `cargo build` doesn't try
// to compile them. See `docs/build-status.md` for the migration list.
//
//   cargo build --features legacy
//
#[cfg(feature = "legacy")]
pub mod hybrid_ratchet;
#[cfg(feature = "legacy")]
pub mod secure_message;
#[cfg(feature = "legacy")]
pub mod file_transfer;
#[cfg(feature = "legacy")]
pub mod audio;
#[cfg(feature = "legacy")]
pub mod sas;
#[cfg(feature = "legacy")]
pub mod oob_secrets;

// WebRTC-backed calling. Behind a feature flag because the in-tree
// implementation hasn't been ported to webrtc 0.14 yet — see
// `src/calling/mod.rs` for the audit notes. `cargo build --features
// calling` is the only way to even attempt it.
#[cfg(feature = "calling")]
pub mod calling;

// JNI Bridge (Only compile for Android targets)
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod jni_api;
