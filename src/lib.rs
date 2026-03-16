// ─── Core production modules (alpha spine) ───
pub mod native_contract;
pub mod relay_protocol;
pub mod relay_security;

// ─── Security and storage primitives ───
pub mod security;
pub mod storage;
pub mod crypto;

// ─── JNI bridge (Android only) ───
#[cfg(target_os = "android")]
pub mod jni_api;

// ─── Standalone utilities ───
pub mod config;
pub mod errors;
pub mod logging;
pub mod sas;
pub mod oob_secrets;
pub mod ephemeral_keys;

// ─── Legacy messaging modules (pre-native_contract path) ───
pub mod dilithium_identity;
pub mod hybrid_ratchet;
pub mod secure_message;
pub mod file_transfer;
pub mod audio;

// Re-exports needed by file_transfer.rs and audio.rs
pub use hybrid_ratchet::{HybridRatchet, PQ_REKEY_PERIOD};

// ─── Extended modules ───
pub mod identity;
pub mod groups;
pub mod audit;
pub mod calling;

// ─── Test infrastructure (cfg(test) only: uses dev-dependencies proptest/tempfile) ───
#[cfg(test)]
pub mod testing;

// ─── Quarantined: network/p2p_node requires libp2p API update ───
// pub mod network;
