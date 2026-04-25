// Core protocol modules
pub mod hybrid_ratchet;
pub mod secure_message;
pub mod file_transfer;
pub mod audio;
pub mod errors;
pub mod logging;
pub mod config;
pub mod ephemeral_keys;
pub mod sas;
pub mod oob_secrets;

// Identity, groups, networking, storage, security
pub mod identity;
pub mod groups;
pub mod onboarding;
pub mod network;
pub mod storage;
pub mod security;

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
