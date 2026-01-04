pub mod hybrid_ratchet;
pub mod secure_message;
pub mod file_transfer;
pub mod audio;
pub mod identity;
pub mod error;
pub mod logging;
pub mod config;
pub mod ephemeral_keys;
pub mod sas;
pub mod oob_secret;

// New Modules
pub mod calling; // Contains WebRTC & Signaling
pub mod network; // Contains libp2p node

// JNI Bridge (Only compile for Android targets)
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod jni_api;
