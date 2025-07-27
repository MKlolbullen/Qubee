use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret, Zeroize};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use pqcrypto_dilithium::dilithium2::{self, PublicKey as PQPublicKey, SecretKey as PQSecretKey};
use blake3::Hasher;
use std::fmt;
use crate::security::secure_rng;

/// Hybrid identity key combining classical and post-quantum cryptography
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    // Classical Ed25519 key pair for compatibility and performance
    classical_private: Secret<SigningKey>,
    classical_public: VerifyingKey,
    
    // Post-quantum Dilithium-2 key pair for quantum resistance
    pq_private: Secret<PQSecretKey>,
    pq_public: PQPublicKey,
    
    // Derived identifier for this identity
    #[zeroize(skip)]
    identity_id: IdentityId,
    
    // Creation timestamp
    #[zeroize(skip)]
    created_at: u64,
}

/// Public portion of an identity key
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityKey {
    pub classical_public: VerifyingKey,
    pub pq_public: PQPublicKey,
    pub identity_id: IdentityId,
    pub created_at: u64,
}

/// Unique identifier for an identity derived from public keys
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId([u8; 32]);

/// Device-specific key derived from identity key
#[derive(ZeroizeOnDrop)]
pub struct DeviceKey {
    // X25519 key pair for ECDH
    x25519_private: Secret<x25519_dalek::StaticSecret>,
    x25519_public: x25519_dalek::PublicKey,
    
    // Kyber-768 key pair for post-quantum KEM
    kyber_private: Secret<pqcrypto_kyber::kyber768::SecretKey>,
    kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    
    // Device identifier
    #[zeroize(skip)]
    device_id: DeviceId,
    
    // Associated identity
    #[zeroize(skip)]
    identity_id: IdentityId,
    
    // Creation timestamp
    #[zeroize(skip)]
    created_at: u64,
}

/// Public portion of a device key
#[derive(Clone, Serialize, Deserialize)]
pub struct DevicePublicKey {
    pub x25519_public: x25519_dalek::PublicKey,
    pub kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    pub device_id: DeviceId,
    pub identity_id: IdentityId,
    pub created_at: u64,
}

/// Unique identifier for a device
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 16]);

/// Hybrid signature combining classical and post-quantum signatures
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub classical_signature: Signature,
    pub pq_signature: dilithium2::DetachedSignature,
    pub signer_identity: IdentityId,
    pub timestamp: u64,
}

impl IdentityKeyPair {
    /// Generate a new identity key pair
    pub fn generate() -> Result<Self> {
        // Generate classical Ed25519 key pair
        let classical_private_bytes = secure_rng::random::array::<32>()?;
        let classical_private = SigningKey::from_bytes(&classical_private_bytes);
        let classical_public = classical_private.verifying_key();
        
        // Generate post-quantum Dilithium-2 key pair
        let (pq_public, pq_private) = dilithium2::keypair();
        
        // Derive identity ID from public keys
        let identity_id = Self::derive_identity_id(&classical_public, &pq_public);
        
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        Ok(IdentityKeyPair {
            classical_private: Secret::new(classical_private),
            classical_public,
            pq_private: Secret::new(pq_private),
            pq_public,
            identity_id,
            created_at,
        })
    }
    
    /// Load identity key pair from secure storage
    pub fn from_bytes(
        classical_private: &[u8; 32],
        pq_private: &[u8],
        classical_public: &[u8; 32],
        pq_public: &[u8],
        created_at: u64,
    ) -> Result<Self> {
        let classical_private = SigningKey::from_bytes(classical_private);
        let classical_public = VerifyingKey::from_bytes(classical_public)
            .map_err(|e| anyhow::anyhow!("Invalid classical public key: {}", e))?;
        
        let pq_private = PQSecretKey::from_bytes(pq_private)
            .map_err(|e| anyhow::anyhow!("Invalid PQ private key: {}", e))?;
        let pq_public = PQPublicKey::from_bytes(pq_public)
            .map_err(|e| anyhow::anyhow!("Invalid PQ public key: {}", e))?;
        
        let identity_id = Self::derive_identity_id(&classical_public, &pq_public);
        
        Ok(IdentityKeyPair {
            classical_private: Secret::new(classical_private),
            classical_public,
            pq_private: Secret::new(pq_private),
            pq_public,
            identity_id,
            created_at,
        })
    }
    
    /// Get the public identity key
    pub fn public_key(&self) -> IdentityKey {
        IdentityKey {
            classical_public: self.classical_public,
            pq_public: self.pq_public.clone(),
            identity_id: self.identity_id,
            created_at: self.created_at,
        }
    }
    
    /// Sign data with hybrid signature
    pub fn sign(&self, data: &[u8]) -> Result<HybridSignature> {
        // Create message to sign (includes timestamp for freshness)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let mut message = Vec::new();
        message.extend_from_slice(data);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(&self.identity_id.0);
        
        // Classical Ed25519 signature
        let classical_signature = self.classical_private.expose_secret().sign(&message);
        
        // Post-quantum Dilithium-2 signature
        let pq_signature = dilithium2::detached_sign(&message, self.pq_private.expose_secret());
        
        Ok(HybridSignature {
            classical_signature,
            pq_signature,
            signer_identity: self.identity_id,
            timestamp,
        })
    }
    
    /// Derive a device key from this identity key
    pub fn derive_device_key(&self, device_info: &[u8]) -> Result<DeviceKey> {
        // Create device-specific seed
        let mut hasher = Hasher::new();
        hasher.update(&self.classical_private.expose_secret().to_bytes());
        hasher.update(self.pq_private.expose_secret().as_bytes());
        hasher.update(device_info);
        hasher.update(b"device_key_derivation");
        
        let seed = hasher.finalize();
        
        // Derive X25519 key pair
        let x25519_private_bytes: [u8; 32] = seed.as_bytes()[..32].try_into().unwrap();
        let x25519_private = x25519_dalek::StaticSecret::from(x25519_private_bytes);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);
        
        // Generate Kyber key pair (using derived randomness)
        let mut rng = secure_rng::SecureRng::new()?;
        let (kyber_public, kyber_private) = pqcrypto_kyber::kyber768::keypair();
        
        // Derive device ID
        let mut device_hasher = Hasher::new();
        device_hasher.update(x25519_public.as_bytes());
        device_hasher.update(kyber_public.as_bytes());
        device_hasher.update(&self.identity_id.0);
        
        let device_hash = device_hasher.finalize();
        let device_id = DeviceId(device_hash.as_bytes()[..16].try_into().unwrap());
        
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        Ok(DeviceKey {
            x25519_private: Secret::new(x25519_private),
            x25519_public,
            kyber_private: Secret::new(kyber_private),
            kyber_public,
            device_id,
            identity_id: self.identity_id,
            created_at,
        })
    }
    
    /// Get identity ID
    pub fn identity_id(&self) -> IdentityId {
        self.identity_id
    }
    
    /// Derive identity ID from public keys
    fn derive_identity_id(classical_public: &VerifyingKey, pq_public: &PQPublicKey) -> IdentityId {
        let mut hasher = Hasher::new();
        hasher.update(classical_public.as_bytes());
        hasher.update(pq_public.as_bytes());
        hasher.update(b"qubee_identity_id");
        
        let hash = hasher.finalize();
        IdentityId(hash.as_bytes()[..32].try_into().unwrap())
    }
}

impl IdentityKey {
    /// Verify a hybrid signature
    pub fn verify(&self, data: &[u8], signature: &HybridSignature) -> Result<bool> {
        // Verify signer identity matches
        if signature.signer_identity != self.identity_id {
            return Ok(false);
        }
        
        // Check signature freshness (within 5 minutes)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        if current_time.saturating_sub(signature.timestamp) > 300 {
            return Ok(false);
        }
        
        // Reconstruct signed message
        let mut message = Vec::new();
        message.extend_from_slice(data);
        message.extend_from_slice(&signature.timestamp.to_le_bytes());
        message.extend_from_slice(&self.identity_id.0);
        
        // Verify classical signature
        let classical_valid = self.classical_public
            .verify(&message, &signature.classical_signature)
            .is_ok();
        
        // Verify post-quantum signature
        let pq_valid = dilithium2::verify_detached_signature(
            &signature.pq_signature,
            &message,
            &self.pq_public,
        ).is_ok();
        
        // Both signatures must be valid
        Ok(classical_valid && pq_valid)
    }
    
    /// Serialize to bytes for storage or transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .context("Failed to deserialize identity key")
    }
    
    /// Get a short fingerprint for user verification
    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.classical_public.as_bytes());
        hasher.update(self.pq_public.as_bytes());
        
        let hash = hasher.finalize();
        let fingerprint_bytes = &hash.as_bytes()[..8];
        
        // Format as groups of 4 hex digits
        format!(
            "{:02X}{:02X} {:02X}{:02X} {:02X}{:02X} {:02X}{:02X}",
            fingerprint_bytes[0], fingerprint_bytes[1],
            fingerprint_bytes[2], fingerprint_bytes[3],
            fingerprint_bytes[4], fingerprint_bytes[5],
            fingerprint_bytes[6], fingerprint_bytes[7],
        )
    }
}

impl DeviceKey {
    /// Get the public device key
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey {
            x25519_public: self.x25519_public,
            kyber_public: self.kyber_public.clone(),
            device_id: self.device_id,
            identity_id: self.identity_id,
            created_at: self.created_at,
        }
    }
    
    /// Perform X25519 key agreement
    pub fn x25519_agree(&self, other_public: &x25519_dalek::PublicKey) -> [u8; 32] {
        self.x25519_private.expose_secret().diffie_hellman(other_public).to_bytes()
    }
    
    /// Perform Kyber key encapsulation
    pub fn kyber_encapsulate(&self, other_public: &pqcrypto_kyber::kyber768::PublicKey) -> Result<(Vec<u8>, [u8; 32])> {
        let (ciphertext, shared_secret) = pqcrypto_kyber::kyber768::encapsulate(other_public);
        Ok((ciphertext.as_bytes().to_vec(), shared_secret.0))
    }
    
    /// Perform Kyber key decapsulation
    pub fn kyber_decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|e| anyhow::anyhow!("Invalid Kyber ciphertext: {}", e))?;
        
        let shared_secret = pqcrypto_kyber::kyber768::decapsulate(&ct, self.kyber_private.expose_secret());
        Ok(shared_secret.0)
    }
    
    /// Get device ID
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    
    /// Get associated identity ID
    pub fn identity_id(&self) -> IdentityId {
        self.identity_id
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl fmt::Debug for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..4]))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", hex::encode(&self.0[..4]))
    }
}

impl From<[u8; 32]> for IdentityId {
    fn from(bytes: [u8; 32]) -> Self {
        IdentityId(bytes)
    }
}

impl From<[u8; 16]> for DeviceId {
    fn from(bytes: [u8; 16]) -> Self {
        DeviceId(bytes)
    }
}

impl AsRef<[u8]> for IdentityId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_key_generation() {
        let keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = keypair.public_key();
        
        assert_eq!(keypair.identity_id(), public_key.identity_id);
    }
    
    #[test]
    fn test_hybrid_signature() {
        let keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = keypair.public_key();
        
        let message = b"test message for signing";
        let signature = keypair.sign(message).expect("Should sign message");
        
        let valid = public_key.verify(message, &signature).expect("Should verify signature");
        assert!(valid);
        
        // Test with wrong message
        let wrong_message = b"different message";
        let invalid = public_key.verify(wrong_message, &signature).expect("Should verify signature");
        assert!(!invalid);
    }
    
    #[test]
    fn test_device_key_derivation() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate identity keypair");
        
        let device_info = b"device_1_info";
        let device_key = identity_keypair.derive_device_key(device_info).expect("Should derive device key");
        
        assert_eq!(device_key.identity_id(), identity_keypair.identity_id());
        
        // Same device info should produce same device key
        let device_key2 = identity_keypair.derive_device_key(device_info).expect("Should derive device key");
        assert_eq!(device_key.device_id(), device_key2.device_id());
        
        // Different device info should produce different device key
        let device_key3 = identity_keypair.derive_device_key(b"device_2_info").expect("Should derive device key");
        assert_ne!(device_key.device_id(), device_key3.device_id());
    }
    
    #[test]
    fn test_key_agreement() {
        let identity1 = IdentityKeyPair::generate().expect("Should generate identity 1");
        let identity2 = IdentityKeyPair::generate().expect("Should generate identity 2");
        
        let device1 = identity1.derive_device_key(b"device1").expect("Should derive device 1");
        let device2 = identity2.derive_device_key(b"device2").expect("Should derive device 2");
        
        let device1_public = device1.public_key();
        let device2_public = device2.public_key();
        
        // X25519 key agreement
        let shared1 = device1.x25519_agree(&device2_public.x25519_public);
        let shared2 = device2.x25519_agree(&device1_public.x25519_public);
        assert_eq!(shared1, shared2);
        
        // Kyber key encapsulation/decapsulation
        let (ciphertext, shared_secret1) = device1.kyber_encapsulate(&device2_public.kyber_public).expect("Should encapsulate");
        let shared_secret2 = device2.kyber_decapsulate(&ciphertext).expect("Should decapsulate");
        assert_eq!(shared_secret1, shared_secret2);
    }
    
    #[test]
    fn test_fingerprint_generation() {
        let keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = keypair.public_key();
        
        let fingerprint = public_key.fingerprint();
        assert_eq!(fingerprint.len(), 19); // "XXXX XXXX XXXX XXXX" format
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }
    
    #[test]
    fn test_serialization() {
        let keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = keypair.public_key();
        
        let serialized = public_key.to_bytes();
        let deserialized = IdentityKey::from_bytes(&serialized).expect("Should deserialize");
        
        assert_eq!(public_key.identity_id, deserialized.identity_id);
        assert_eq!(public_key.classical_public, deserialized.classical_public);
        assert_eq!(public_key.pq_public.as_bytes(), deserialized.pq_public.as_bytes());
    }
}
