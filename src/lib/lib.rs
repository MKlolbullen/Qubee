//! # Qubee Enhanced - Post-Quantum Secure Messaging Library
//! 
//! A comprehensive, security-hardened implementation of a post-quantum secure messaging
//! system with enhanced security features, formal verification support, and comprehensive
//! audit capabilities.
//! 
//! ## Features
//! 
//! - **Post-quantum cryptography**: Kyber-768 KEM and Dilithium-2 signatures
//! - **Hybrid security**: Combines classical and post-quantum algorithms
//! - **Enhanced memory security**: Secure memory allocation and zeroization
//! - **Secure key storage**: Encrypted key storage with platform integration
//! - **Comprehensive auditing**: Built-in security audit framework
//! - **Traffic analysis resistance**: Cover traffic and padding mechanisms
//! - **Formal verification**: Annotations for formal verification tools
//! 
//! ## Security Warning
//! 
//! This is an enhanced version of the experimental Qubee library. While it includes
//! significant security improvements, it should still undergo professional security
//! audit before production use.
//! 
//! ## Example Usage
//! 
//! ```rust,no_run
//! use qubee_enhanced::{SecureMessenger, SecurityAuditor};
//! 
//! // Create a secure messenger instance
//! let mut messenger = SecureMessenger::new()?;
//! 
//! // Run security audit
//! let mut auditor = SecurityAuditor::new();
//! let report = auditor.run_audit()?;
//! 
//! println!("Security score: {}", report.summary.overall_score);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![deny(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

// Re-export important types and functions
pub use crate::crypto::enhanced_ratchet::{EnhancedHybridRatchet, RatchetState, MessageId};
pub use crate::security::secure_rng::{SecureRng, GlobalSecureRng, random};
pub use crate::security::secure_memory::{SecureAllocator, SecureBuffer, SecureString};
pub use crate::storage::secure_keystore::{SecureKeyStore, KeyType, KeyMetadata, KeyUsage};
pub use crate::audit::security_auditor::{SecurityAuditor, AuditReport, SecurityFinding, Severity};

// Module declarations
pub mod security {
    //! Security-related modules for enhanced protection
    
    pub mod secure_rng;
    pub mod secure_memory;
}

pub mod crypto {
    //! Cryptographic implementations and protocols
    
    pub mod enhanced_ratchet;
}

pub mod storage {
    //! Secure storage implementations
    
    pub mod secure_keystore;
}

pub mod audit {
    //! Security audit and compliance checking
    
    pub mod security_auditor;
}

pub mod network {
    //! Network layer with enhanced security features
    
    // TODO: Implement enhanced networking modules
}

pub mod testing {
    //! Testing utilities and frameworks
    
    // TODO: Implement comprehensive testing framework
}

// Core error types
use thiserror::Error;

/// Main error type for the Qubee Enhanced library
#[derive(Error, Debug)]
pub enum QubeeError {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),
    
    /// Network operation failed
    #[error("Network error: {0}")]
    Network(String),
    
    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(String),
    
    /// Security violation detected
    #[error("Security violation: {0}")]
    Security(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, QubeeError>;

/// Main secure messenger interface
pub struct SecureMessenger {
    ratchet: EnhancedHybridRatchet,
    keystore: SecureKeyStore,
    config: MessengerConfig,
}

/// Configuration for the secure messenger
#[derive(Debug, Clone)]
pub struct MessengerConfig {
    /// Maximum number of skipped messages to handle
    pub max_skip_messages: usize,
    
    /// Enable cover traffic generation
    pub enable_cover_traffic: bool,
    
    /// Enable formal verification checks
    pub enable_formal_verification: bool,
    
    /// Security audit interval in seconds
    pub audit_interval: u64,
    
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
}

impl Default for MessengerConfig {
    fn default() -> Self {
        MessengerConfig {
            max_skip_messages: 1000,
            enable_cover_traffic: true,
            enable_formal_verification: false,
            audit_interval: 3600, // 1 hour
            key_rotation_interval: 86400, // 24 hours
        }
    }
}

impl SecureMessenger {
    /// Create a new secure messenger with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(MessengerConfig::default())
    }
    
    /// Create a secure messenger with custom configuration
    pub fn with_config(config: MessengerConfig) -> Result<Self> {
        let ratchet = EnhancedHybridRatchet::new();
        
        // Create keystore in default location
        let keystore_path = dirs::data_dir()
            .ok_or_else(|| QubeeError::Configuration("Cannot determine data directory".to_string()))?
            .join("qubee")
            .join("keystore.db");
        
        let keystore = SecureKeyStore::new(keystore_path)
            .map_err(|e| QubeeError::Storage(e.to_string()))?;
        
        Ok(SecureMessenger {
            ratchet,
            keystore,
            config,
        })
    }
    
    /// Initialize the messenger for sending (Alice role)
    pub fn initialize_sender(
        &mut self,
        shared_secret: &[u8],
        remote_dh_key: &[u8; 32],
        remote_pq_key: &[u8],
    ) -> Result<()> {
        // Convert keys to proper types
        let dh_key = x25519_dalek::PublicKey::from(*remote_dh_key);
        let pq_key = pqcrypto_kyber::kyber768::PublicKey::from_bytes(remote_pq_key)
            .map_err(|e| QubeeError::Cryptographic(format!("Invalid PQ key: {}", e)))?;
        
        self.ratchet
            .initialize_sender(shared_secret, &dh_key, &pq_key)
            .map_err(|e| QubeeError::Cryptographic(e.to_string()))?;
        
        Ok(())
    }
    
    /// Initialize the messenger for receiving (Bob role)
    pub fn initialize_receiver(
        &mut self,
        shared_secret: &[u8],
        dh_private_key: &[u8; 32],
        pq_private_key: &[u8],
    ) -> Result<()> {
        // Convert keys to proper types
        let dh_key = x25519_dalek::StaticSecret::from(*dh_private_key);
        let pq_key = pqcrypto_kyber::kyber768::SecretKey::from_bytes(pq_private_key)
            .map_err(|e| QubeeError::Cryptographic(format!("Invalid PQ private key: {}", e)))?;
        
        self.ratchet
            .initialize_receiver(shared_secret, dh_key, pq_key)
            .map_err(|e| QubeeError::Cryptographic(e.to_string()))?;
        
        Ok(())
    }
    
    /// Encrypt a message
    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if !self.ratchet.is_active() {
            return Err(QubeeError::Security("Ratchet not active".to_string()));
        }
        
        let encrypted = self.ratchet
            .encrypt(message, &[])
            .map_err(|e| QubeeError::Cryptographic(e.to_string()))?;
        
        bincode::serialize(&encrypted)
            .map_err(|e| QubeeError::Internal(e.to_string()))
    }
    
    /// Decrypt a message
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.ratchet.is_active() {
            return Err(QubeeError::Security("Ratchet not active".to_string()));
        }
        
        let message: crate::crypto::enhanced_ratchet::RatchetMessage = 
            bincode::deserialize(ciphertext)
                .map_err(|e| QubeeError::Internal(e.to_string()))?;
        
        self.ratchet
            .decrypt(&message, &[])
            .map_err(|e| QubeeError::Cryptographic(e.to_string()))
    }
    
    /// Get the current ratchet state
    pub fn ratchet_state(&self) -> RatchetState {
        self.ratchet.state()
    }
    
    /// Store a key in the secure keystore
    pub fn store_key(
        &mut self,
        key_id: &str,
        key_data: &[u8],
        key_type: KeyType,
        metadata: KeyMetadata,
    ) -> Result<()> {
        self.keystore
            .store_key(key_id, key_data, key_type, metadata)
            .map_err(|e| QubeeError::Storage(e.to_string()))
    }
    
    /// Retrieve a key from the secure keystore
    pub fn retrieve_key(&mut self, key_id: &str) -> Result<Option<Vec<u8>>> {
        match self.keystore
            .retrieve_key(key_id)
            .map_err(|e| QubeeError::Storage(e.to_string()))?
        {
            Some(secret) => Ok(Some(secret.expose_secret().clone())),
            None => Ok(None),
        }
    }
    
    /// Run a security audit
    pub fn run_security_audit(&self) -> Result<AuditReport> {
        let mut auditor = SecurityAuditor::new();
        auditor.run_audit()
            .map_err(|e| QubeeError::Security(e.to_string()))
    }
    
    /// Get messenger configuration
    pub fn config(&self) -> &MessengerConfig {
        &self.config
    }
    
    /// Update messenger configuration
    pub fn update_config(&mut self, config: MessengerConfig) {
        self.config = config;
    }
}

/// Utility functions for common operations
pub mod utils {
    use super::*;
    
    /// Generate a secure random key of specified length
    pub fn generate_random_key(length: usize) -> Result<Vec<u8>> {
        random::bytes(length)
            .map_err(|e| QubeeError::Cryptographic(e.to_string()))
    }
    
    /// Generate a cryptographic hash of data
    pub fn hash_data(data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }
    
    /// Constant-time comparison of byte arrays
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
    
    /// Securely zeroize a byte array
    pub fn secure_zeroize(data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
    }
}

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 2;
pub const VERSION_PATCH: u32 = 0;

/// Library information
pub const LIBRARY_NAME: &str = "Qubee Enhanced";
pub const LIBRARY_DESCRIPTION: &str = "Post-Quantum Secure Messaging Library with Enhanced Security";

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_messenger_creation() {
        let messenger = SecureMessenger::new();
        assert!(messenger.is_ok());
    }
    
    #[test]
    fn test_config_default() {
        let config = MessengerConfig::default();
        assert_eq!(config.max_skip_messages, 1000);
        assert!(config.enable_cover_traffic);
    }
    
    #[test]
    fn test_utility_functions() {
        let key = utils::generate_random_key(32).expect("Should generate key");
        assert_eq!(key.len(), 32);
        
        let hash = utils::hash_data(b"test data");
        assert_eq!(hash.len(), 32);
        
        assert!(utils::constant_time_eq(b"same", b"same"));
        assert!(!utils::constant_time_eq(b"different", b"data"));
    }
    
    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert_eq!(VERSION_MAJOR, 0);
        assert_eq!(VERSION_MINOR, 2);
        assert_eq!(VERSION_PATCH, 0);
    }
}
pub mod jni_api;
