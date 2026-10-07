// Modules that survived the round-9 audit and `cargo check` clean.
pub mod config;
pub mod ephemeral_keys;
pub mod errors;
pub mod groups;
pub mod identity;
pub mod logging;
pub mod network;
pub mod onboarding;
pub mod ratchet;
pub mod security;
pub mod storage;

// Legacy modules from the early prototype. They lean on dependency
// versions and APIs that no longer match Cargo.toml; some reference
// crates that aren't even declared (e.g. `double_ratchet`). Gated
// behind the `legacy` feature so default `cargo build` doesn't try
// to compile them. See `docs/build-status.md` for the migration list.
//
//   cargo build --features legacy
//
#[cfg(feature = "legacy")]
pub mod audio;
#[cfg(feature = "legacy")]
pub mod file_transfer;
#[cfg(feature = "legacy")]
pub mod hybrid_ratchet;
#[cfg(feature = "legacy")]
pub mod oob_secrets;
#[cfg(feature = "legacy")]
pub mod sas;
#[cfg(feature = "legacy")]
pub mod secure_message;

// WebRTC-backed calling. Off by default: the shipped JNI library is
// built without this feature, and video capture is not implemented.
// `cargo test --features calling` covers the gated voice path.
#[cfg(feature = "calling")]
pub mod calling;

// JNI Bridge (Only compile for Android targets, plus opt-in host
// type-check via the `_typecheck_jni` feature flag).
#[cfg(any(target_os = "android", feature = "_typecheck_jni"))]
#[allow(non_snake_case)]
pub mod jni_api;
