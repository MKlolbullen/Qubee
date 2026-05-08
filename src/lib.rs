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
pub mod media_devices;
pub mod crypto;
pub mod sessions;

// WebRTC-backed calling. Behind a feature flag because the in-tree
// implementation hasn't been ported to webrtc 0.14 yet — see
// `src/calling/mod.rs` for the audit notes. `cargo build --features
// calling` is the only way to even attempt it.
#[cfg(feature = "calling")]
pub mod calling;

// JNI Bridge (Only compile for Android targets, plus opt-in host
// type-check via the `_typecheck_jni` feature flag).
#[cfg(any(target_os = "android", feature = "_typecheck_jni"))]
#[allow(non_snake_case)]
pub mod jni_api;
