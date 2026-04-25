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

// Identity, groups, calling, networking, storage, security
pub mod identity;
pub mod groups;
pub mod onboarding;
pub mod calling;
pub mod network;
pub mod storage;
pub mod security;

// JNI Bridge (Only compile for Android targets)
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod jni_api;
