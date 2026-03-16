use anyhow::{Context, Result};
use zeroize::Zeroizing;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use pqcrypto_dilithium::dilithium2::{self, PublicKey as PQPublicKey};
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
use pqcrypto_traits::sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey,
    DetachedSignature as DetachedSignatureTrait,
};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use blake3::Hasher;
use std::fmt;
use crate::security::secure_rng;

// ─── Custom serde helpers for pqcrypto types ─────────────────────────────────

mod serde_pq_dilithium_pubkey {
    use super::*;
    use pqcrypto_dilithium::dilithium2::PublicKey as PQPublicKey;

    pub fn serialize<S: Serializer>(key: &PQPublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PQPublicKey, D::Error> {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
        PQPublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

mod serde_pq_dilithium_detached_sig {
    use super::*;
    use pqcrypto_dilithium::dilithium2::DetachedSignature;

    pub fn serialize<S: Serializer>(sig: &DetachedSignature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DetachedSignature, D::Error> {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
        DetachedSignature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

pub mod serde_kyber_pubkey {
    use super::*;
    use pqcrypto_kyber::kyber768::PublicKey as KyberPublicKey;

    pub fn serialize<S: Serializer>(key: &KyberPublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<KyberPublicKey, D::Error> {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
        KyberPublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// Hybrid identity key combining classical and post-quantum cryptography.
/// Private keys are stored as raw zeroizing byte arrays to avoid trait bound
/// issues with secrecy::Secret and pqcrypto types that don't implement Zeroize.
pub struct IdentityKeyPair {
    /// Ed25519 secret key as raw 32 bytes (zeroized on drop).
    classical_private_bytes: Zeroizing<[u8; 32]>,
    classical_public: VerifyingKey,
    /// Dilithium-2 secret key bytes (zeroized on drop).
    pq_private_bytes: Zeroizing<Vec<u8>>,
    pq_public: PQPublicKey,
    identity_id: IdentityId,
    created_at: u64,
}

/// Public portion of an identity key.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKey {
    pub classical_public: VerifyingKey,
    #[serde(with = "serde_pq_dilithium_pubkey")]
    pub pq_public: PQPublicKey,
    pub identity_id: IdentityId,
    pub created_at: u64,
}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        use pqcrypto_traits::sign::PublicKey as _;
        self.classical_public == other.classical_public
            && self.pq_public.as_bytes() == other.pq_public.as_bytes()
            && self.identity_id == other.identity_id
            && self.created_at == other.created_at
    }
}
impl Eq for IdentityKey {}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKey")
            .field("identity_id", &self.identity_id)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Unique identifier for an identity derived from public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId([u8; 32]);

/// Device-specific key derived from identity key.
/// Private keys stored as raw zeroizing bytes.
pub struct DeviceKey {
    /// X25519 secret key as raw 32 bytes (zeroized on drop).
    x25519_private_bytes: Zeroizing<[u8; 32]>,
    x25519_public: x25519_dalek::PublicKey,
    /// Kyber-768 secret key bytes (zeroized on drop).
    kyber_private_bytes: Zeroizing<Vec<u8>>,
    kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    device_id: DeviceId,
    identity_id: IdentityId,
    created_at: u64,
}

/// Public portion of a device key.
#[derive(Clone, Serialize, Deserialize)]
pub struct DevicePublicKey {
    pub x25519_public: x25519_dalek::PublicKey,
    #[serde(with = "serde_kyber_pubkey")]
    pub kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    pub device_id: DeviceId,
    pub identity_id: IdentityId,
    pub created_at: u64,
}

/// Unique identifier for a device.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 16]);

/// Hybrid signature combining classical and post-quantum signatures.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub classical_signature: Signature,
    #[serde(with = "serde_pq_dilithium_detached_sig")]
    pub pq_signature: dilithium2::DetachedSignature,
    pub signer_identity: IdentityId,
    pub timestamp: u64,
}

// ─── IdentityKeyPair ─────────────────────────────────────────────────────────

impl IdentityKeyPair {
    /// Generate a new identity key pair.
    pub fn generate() -> Result<Self> {
        let classical_private_bytes_raw = secure_rng::random::array::<32>()?;
        let signing_key = SigningKey::from_bytes(&classical_private_bytes_raw);
        let classical_public = signing_key.verifying_key();

        let (pq_public, pq_private) = dilithium2::keypair();
        let pq_private_bytes = Zeroizing::new(pq_private.as_bytes().to_vec());

        let identity_id = Self::derive_identity_id(&classical_public, &pq_public);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(IdentityKeyPair {
            classical_private_bytes: Zeroizing::new(classical_private_bytes_raw),
            classical_public,
            pq_private_bytes,
            pq_public,
            identity_id,
            created_at,
        })
    }

    /// Load identity key pair from secure storage.
    pub fn from_bytes(
        classical_private: &[u8; 32],
        pq_private: &[u8],
        classical_public: &[u8; 32],
        pq_public: &[u8],
        created_at: u64,
    ) -> Result<Self> {
        let classical_public = VerifyingKey::from_bytes(classical_public)
            .map_err(|e| anyhow::anyhow!("Invalid classical public key: {}", e))?;

        // Validate the pq bytes are well-formed.
        let _ = dilithium2::SecretKey::from_bytes(pq_private)
            .map_err(|e| anyhow::anyhow!("Invalid PQ private key: {}", e))?;
        let pq_public = PQPublicKey::from_bytes(pq_public)
            .map_err(|e| anyhow::anyhow!("Invalid PQ public key: {}", e))?;

        let identity_id = Self::derive_identity_id(&classical_public, &pq_public);

        Ok(IdentityKeyPair {
            classical_private_bytes: Zeroizing::new(*classical_private),
            classical_public,
            pq_private_bytes: Zeroizing::new(pq_private.to_vec()),
            pq_public,
            identity_id,
            created_at,
        })
    }

    /// Get the public identity key.
    pub fn public_key(&self) -> IdentityKey {
        IdentityKey {
            classical_public: self.classical_public,
            pq_public: self.pq_public.clone(),
            identity_id: self.identity_id,
            created_at: self.created_at,
        }
    }

    /// Sign data with a hybrid (classical + post-quantum) signature.
    pub fn sign(&self, data: &[u8]) -> Result<HybridSignature> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let mut message = Vec::new();
        message.extend_from_slice(data);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(&self.identity_id.0);

        let signing_key = SigningKey::from_bytes(&*self.classical_private_bytes);
        let classical_signature = signing_key.sign(&message);

        let pq_sk = dilithium2::SecretKey::from_bytes(&self.pq_private_bytes)
            .context("Failed to reconstruct Dilithium secret key for signing")?;
        let pq_signature = dilithium2::detached_sign(&message, &pq_sk);

        Ok(HybridSignature {
            classical_signature,
            pq_signature,
            signer_identity: self.identity_id,
            timestamp,
        })
    }

    /// Derive a device key from this identity key.
    pub fn derive_device_key(&self, device_info: &[u8]) -> Result<DeviceKey> {
        let mut hasher = Hasher::new();
        hasher.update(&*self.classical_private_bytes);
        hasher.update(&self.pq_private_bytes);
        hasher.update(device_info);
        hasher.update(b"device_key_derivation");

        let seed = hasher.finalize();

        let x25519_private_bytes: [u8; 32] = seed.as_bytes()[..32].try_into().unwrap();
        let x25519_private = x25519_dalek::StaticSecret::from(x25519_private_bytes);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);

        let (kyber_public, kyber_private) = pqcrypto_kyber::kyber768::keypair();
        let kyber_private_bytes = Zeroizing::new(kyber_private.as_bytes().to_vec());

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
            x25519_private_bytes: Zeroizing::new(x25519_private_bytes),
            x25519_public,
            kyber_private_bytes,
            kyber_public,
            device_id,
            identity_id: self.identity_id,
            created_at,
        })
    }

    /// Get identity ID.
    pub fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Expose classical private key bytes (for ZK proof generation).
    pub fn classical_private_bytes(&self) -> &[u8; 32] {
        &self.classical_private_bytes
    }

    /// Expose PQ private key bytes (for ZK proof generation).
    pub fn pq_private_bytes(&self) -> &[u8] {
        &self.pq_private_bytes
    }

    fn derive_identity_id(classical_public: &VerifyingKey, pq_public: &PQPublicKey) -> IdentityId {
        let mut hasher = Hasher::new();
        hasher.update(classical_public.as_bytes());
        hasher.update(pq_public.as_bytes());
        hasher.update(b"qubee_identity_id");

        let hash = hasher.finalize();
        IdentityId(hash.as_bytes()[..32].try_into().unwrap())
    }
}

// ─── IdentityKey ─────────────────────────────────────────────────────────────

impl IdentityKey {
    /// Verify a hybrid signature.
    pub fn verify(&self, data: &[u8], signature: &HybridSignature) -> Result<bool> {
        if signature.signer_identity != self.identity_id {
            return Ok(false);
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if current_time.saturating_sub(signature.timestamp) > 300 {
            return Ok(false);
        }

        let mut message = Vec::new();
        message.extend_from_slice(data);
        message.extend_from_slice(&signature.timestamp.to_le_bytes());
        message.extend_from_slice(&self.identity_id.0);

        let classical_valid = self.classical_public
            .verify(&message, &signature.classical_signature)
            .is_ok();

        let pq_valid = dilithium2::verify_detached_signature(
            &signature.pq_signature,
            &message,
            &self.pq_public,
        ).is_ok();

        Ok(classical_valid && pq_valid)
    }

    /// Serialize to bytes for storage or transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .context("Failed to deserialize identity key")
    }

    /// Get a short fingerprint for user verification.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.classical_public.as_bytes());
        hasher.update(self.pq_public.as_bytes());

        let hash = hasher.finalize();
        let fp = &hash.as_bytes()[..8];

        format!(
            "{:02X}{:02X} {:02X}{:02X} {:02X}{:02X} {:02X}{:02X}",
            fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7],
        )
    }
}

// ─── DeviceKey ───────────────────────────────────────────────────────────────

impl DeviceKey {
    /// Get the public device key.
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey {
            x25519_public: self.x25519_public,
            kyber_public: self.kyber_public.clone(),
            device_id: self.device_id,
            identity_id: self.identity_id,
            created_at: self.created_at,
        }
    }

    /// Perform X25519 key agreement.
    pub fn x25519_agree(&self, other_public: &x25519_dalek::PublicKey) -> [u8; 32] {
        let sk = x25519_dalek::StaticSecret::from(*self.x25519_private_bytes);
        sk.diffie_hellman(other_public).to_bytes()
    }

    /// Perform Kyber key encapsulation.
    pub fn kyber_encapsulate(&self, other_public: &pqcrypto_kyber::kyber768::PublicKey) -> Result<(Vec<u8>, [u8; 32])> {
        let (shared_secret, ciphertext) = pqcrypto_kyber::kyber768::encapsulate(other_public);
        let ss_bytes: [u8; 32] = shared_secret.as_bytes().try_into()
            .map_err(|_| anyhow::anyhow!("Kyber shared secret length mismatch"))?;
        Ok((ciphertext.as_bytes().to_vec(), ss_bytes))
    }

    /// Perform Kyber key decapsulation.
    pub fn kyber_decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|e| anyhow::anyhow!("Invalid Kyber ciphertext: {}", e))?;
        let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(&self.kyber_private_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to reconstruct Kyber secret key: {}", e))?;
        let shared_secret = pqcrypto_kyber::kyber768::decapsulate(&ct, &sk);
        let ss_bytes: [u8; 32] = shared_secret.as_bytes().try_into()
            .map_err(|_| anyhow::anyhow!("Kyber shared secret length mismatch"))?;
        Ok(ss_bytes)
    }

    /// Get device ID.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Get associated identity ID.
    pub fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Reconstruct an x25519 `StaticSecret` from the stored bytes.
    pub fn x25519_static_secret(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(*self.x25519_private_bytes)
    }

    /// Reconstruct a `kyber768::SecretKey` from the stored bytes.
    pub fn kyber_secret_key(&self) -> Result<pqcrypto_kyber::kyber768::SecretKey> {
        use pqcrypto_traits::kem::SecretKey as _;
        pqcrypto_kyber::kyber768::SecretKey::from_bytes(&self.kyber_private_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid kyber secret key bytes: {:?}", e))
    }
}

// ─── Display / Debug ─────────────────────────────────────────────────────────

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
    fn from(bytes: [u8; 32]) -> Self { IdentityId(bytes) }
}

impl From<[u8; 16]> for DeviceId {
    fn from(bytes: [u8; 16]) -> Self { DeviceId(bytes) }
}

impl AsRef<[u8]> for IdentityId {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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

        let device_key2 = identity_keypair.derive_device_key(device_info).expect("Should derive device key");
        assert_eq!(device_key.device_id(), device_key2.device_id());

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

        let shared1 = device1.x25519_agree(&device2_public.x25519_public);
        let shared2 = device2.x25519_agree(&device1_public.x25519_public);
        assert_eq!(shared1, shared2);

        let (ciphertext, shared_secret1) = device1.kyber_encapsulate(&device2_public.kyber_public).expect("Should encapsulate");
        let shared_secret2 = device2.kyber_decapsulate(&ciphertext).expect("Should decapsulate");
        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_fingerprint_generation() {
        let keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let public_key = keypair.public_key();
        let fingerprint = public_key.fingerprint();
        assert_eq!(fingerprint.len(), 19);
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
