//! Hybrid identity keys (Ed25519 + Dilithium-2) and the device-key
//! derivation that hangs off them. Refactored in round Q to play
//! nicely with `secrecy 0.10` (no more `Secret<NonCopyType>`), the
//! pqcrypto crates' lack of a `serde` feature, and the missing
//! `Debug`/`Zeroize` derives.
//!
//! The trick: store private key material as raw byte buffers on the
//! struct (which `zeroize` understands directly) and reconstruct the
//! typed pqcrypto values lazily inside `sign` / `derive_device_key`.
//! Public types still expose the strongly-typed `IdentityKey` and
//! `HybridSignature` to the rest of the crate; serde for those uses
//! `#[serde(with = "...")]` modules that round-trip the pq fields
//! through their byte representation.

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium2::{self};
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

use crate::security::secure_rng;

// ---------------------------------------------------------------------------
// Public-facing types
// ---------------------------------------------------------------------------

/// Public portion of an identity key. `Eq` is dropped because the
/// inner `dilithium2::PublicKey` doesn't impl it; `PartialEq` does
/// fine for byte-equality comparisons used at the call sites.
#[derive(Clone, PartialEq)]
pub struct IdentityKey {
    pub classical_public: VerifyingKey,
    pub pq_public: dilithium2::PublicKey,
    pub identity_id: IdentityId,
    pub created_at: u64,
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKey")
            .field("identity_id", &self.identity_id)
            .field("created_at", &self.created_at)
            .field("pq_public_len", &self.pq_public.as_bytes().len())
            .finish_non_exhaustive()
    }
}

/// Unique identifier for an identity derived from its public keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityId(pub(crate) [u8; 32]);

/// Public portion of a device key (one device per identity).
#[derive(Clone)]
pub struct DevicePublicKey {
    pub x25519_public: x25519_dalek::PublicKey,
    pub kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    pub device_id: DeviceId,
    pub identity_id: IdentityId,
    pub created_at: u64,
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevicePublicKey")
            .field("device_id", &self.device_id)
            .field("identity_id", &self.identity_id)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Unique identifier for a device.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub(crate) [u8; 16]);

/// Hybrid signature combining classical and post-quantum signatures.
#[derive(Clone)]
pub struct HybridSignature {
    pub classical_signature: Signature,
    pub pq_signature: dilithium2::DetachedSignature,
    pub signer_identity: IdentityId,
    pub timestamp: u64,
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSignature")
            .field("signer_identity", &self.signer_identity)
            .field("timestamp", &self.timestamp)
            .field("pq_sig_len", &self.pq_signature.as_bytes().len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Private keypair (zeroising on drop)
// ---------------------------------------------------------------------------

/// Hybrid identity key combining classical (Ed25519) and post-quantum
/// (Dilithium-2) cryptography. Private material lives in raw byte
/// buffers on the struct so `Zeroize` can reach it on drop without
/// needing `secrecy::SecretBox` (which the pqcrypto secret types
/// don't satisfy because they don't impl `Zeroize` directly).
pub struct IdentityKeyPair {
    classical_private_bytes: [u8; 32],
    classical_public: VerifyingKey,
    /// Raw bytes of `dilithium2::SecretKey`. Reconstructed via
    /// `dilithium2::SecretKey::from_bytes` inside `sign`.
    pq_private_bytes: Vec<u8>,
    pq_public: dilithium2::PublicKey,
    identity_id: IdentityId,
    created_at: u64,
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.classical_private_bytes.zeroize();
        self.pq_private_bytes.zeroize();
    }
}

/// Encrypted-at-rest representation of an [`IdentityKeyPair`]. Lives
/// in the secure keystore only; bytes are never exposed to Kotlin / JNI.
#[derive(Serialize, Deserialize)]
struct PersistedIdentitySecrets {
    classical_private: [u8; 32],
    pq_private: Vec<u8>,
    classical_public: [u8; 32],
    pq_public: Vec<u8>,
    created_at: u64,
}

impl IdentityKeyPair {
    /// Generate a new identity key pair.
    pub fn generate() -> Result<Self> {
        let classical_private_bytes = secure_rng::random::array::<32>()?;
        let classical_private = SigningKey::from_bytes(&classical_private_bytes);
        let classical_public = classical_private.verifying_key();

        let (pq_public, pq_private) = dilithium2::keypair();

        let identity_id = Self::derive_identity_id(&classical_public, &pq_public);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(IdentityKeyPair {
            classical_private_bytes,
            classical_public,
            pq_private_bytes: pq_private.as_bytes().to_vec(),
            pq_public,
            identity_id,
            created_at,
        })
    }

    /// Reconstruct from raw byte buffers (used by the secure keystore
    /// and any future identity-import path).
    pub fn from_bytes(
        classical_private: &[u8; 32],
        pq_private: &[u8],
        classical_public: &[u8; 32],
        pq_public: &[u8],
        created_at: u64,
    ) -> Result<Self> {
        let classical_priv = SigningKey::from_bytes(classical_private);
        let classical_pub = VerifyingKey::from_bytes(classical_public)
            .map_err(|e| anyhow!("Invalid classical public key: {e}"))?;
        // Make sure both sides agree.
        if classical_priv.verifying_key() != classical_pub {
            return Err(anyhow!("classical pub/priv mismatch"));
        }
        let pq_pub = dilithium2::PublicKey::from_bytes(pq_public)
            .map_err(|e| anyhow!("Invalid PQ public key: {e}"))?;
        // Validate the secret key length by attempting to reconstruct it.
        let _ = dilithium2::SecretKey::from_bytes(pq_private)
            .map_err(|e| anyhow!("Invalid PQ private key: {e}"))?;

        let identity_id = Self::derive_identity_id(&classical_pub, &pq_pub);

        Ok(IdentityKeyPair {
            classical_private_bytes: *classical_private,
            classical_public: classical_pub,
            pq_private_bytes: pq_private.to_vec(),
            pq_public: pq_pub,
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

    /// Sign data with hybrid (Ed25519 + Dilithium-2) signature.
    pub fn sign(&self, data: &[u8]) -> Result<HybridSignature> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let mut message = Vec::with_capacity(data.len() + 8 + 32);
        message.extend_from_slice(data);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(&self.identity_id.0);

        let classical_priv = SigningKey::from_bytes(&self.classical_private_bytes);
        let classical_signature = classical_priv.sign(&message);

        let pq_priv = dilithium2::SecretKey::from_bytes(&self.pq_private_bytes)
            .map_err(|e| anyhow!("invalid persisted pq sk: {e}"))?;
        let pq_signature = dilithium2::detached_sign(&message, &pq_priv);

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
        hasher.update(&self.classical_private_bytes);
        hasher.update(&self.pq_private_bytes);
        hasher.update(device_info);
        hasher.update(b"device_key_derivation");
        let seed = hasher.finalize();

        let x25519_private_bytes: [u8; 32] = seed.as_bytes()[..32].try_into().unwrap();
        let x25519_private = x25519_dalek::StaticSecret::from(x25519_private_bytes);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);

        // Kyber key derivation: pqcrypto-kyber doesn't expose a
        // deterministic seeded keygen, so we bite the bullet and use
        // its OS-randomness keypair. Future work: derive
        // deterministically from `seed` once kyber-pure exposes it.
        let (kyber_public, kyber_private) = pqcrypto_kyber::kyber768::keypair();

        let mut device_hasher = Hasher::new();
        device_hasher.update(x25519_public.as_bytes());
        use pqcrypto_traits::kem::PublicKey as _;
        device_hasher.update(kyber_public.as_bytes());
        device_hasher.update(&self.identity_id.0);

        let device_hash = device_hasher.finalize();
        let device_id = DeviceId(device_hash.as_bytes()[..16].try_into().unwrap());
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        use pqcrypto_traits::kem::SecretKey as _;
        Ok(DeviceKey {
            x25519_private_bytes,
            x25519_public,
            kyber_private_bytes: kyber_private.as_bytes().to_vec(),
            kyber_public,
            device_id,
            identity_id: self.identity_id,
            created_at,
        })
    }

    /// Stable identifier for this identity.
    pub fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    /// Serialise the full keypair to a byte buffer suitable for the
    /// encrypted [`crate::storage::secure_keystore::SecureKeyStore`].
    /// Bytes contain raw private material — the keystore must wrap
    /// them in ChaCha20-Poly1305 before any disk write.
    pub fn serialize_for_keystore(&self) -> Result<Vec<u8>> {
        let secrets = PersistedIdentitySecrets {
            classical_private: self.classical_private_bytes,
            pq_private: self.pq_private_bytes.clone(),
            classical_public: self.classical_public.to_bytes(),
            pq_public: self.pq_public.as_bytes().to_vec(),
            created_at: self.created_at,
        };
        bincode::serialize(&secrets).context("identity secrets serialize failed")
    }

    /// Inverse of [`serialize_for_keystore`].
    pub fn deserialize_from_keystore(bytes: &[u8]) -> Result<Self> {
        let s: PersistedIdentitySecrets =
            bincode::deserialize(bytes).context("identity secrets deserialize failed")?;
        Self::from_bytes(
            &s.classical_private,
            &s.pq_private,
            &s.classical_public,
            &s.pq_public,
            s.created_at,
        )
    }

    fn derive_identity_id(
        classical_public: &VerifyingKey,
        pq_public: &dilithium2::PublicKey,
    ) -> IdentityId {
        let mut hasher = Hasher::new();
        hasher.update(classical_public.as_bytes());
        hasher.update(pq_public.as_bytes());
        hasher.update(b"qubee_identity_id");
        let hash = hasher.finalize();
        IdentityId(hash.as_bytes()[..32].try_into().unwrap())
    }
}

impl IdentityKey {
    /// Default acceptable signature age (5 minutes) for ratcheted
    /// message flows. Use [`verify_with_max_age`] for QR / onboarding
    /// flows that need a longer window.
    const DEFAULT_MAX_SIGNATURE_AGE_SECS: u64 = 300;

    /// Verify a hybrid signature with the default 5-minute freshness window.
    pub fn verify(&self, data: &[u8], signature: &HybridSignature) -> Result<bool> {
        self.verify_with_max_age(data, signature, Self::DEFAULT_MAX_SIGNATURE_AGE_SECS)
    }

    /// Verify a hybrid signature with a caller-supplied freshness window.
    pub fn verify_with_max_age(
        &self,
        data: &[u8],
        signature: &HybridSignature,
        max_age_secs: u64,
    ) -> Result<bool> {
        if signature.signer_identity != self.identity_id {
            return Ok(false);
        }
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if current_time.saturating_sub(signature.timestamp) > max_age_secs {
            return Ok(false);
        }

        let mut message = Vec::with_capacity(data.len() + 8 + 32);
        message.extend_from_slice(data);
        message.extend_from_slice(&signature.timestamp.to_le_bytes());
        message.extend_from_slice(&self.identity_id.0);

        let classical_valid = self
            .classical_public
            .verify(&message, &signature.classical_signature)
            .is_ok();
        let pq_valid = dilithium2::verify_detached_signature(
            &signature.pq_signature,
            &message,
            &self.pq_public,
        )
        .is_ok();
        Ok(classical_valid && pq_valid)
    }

    /// Serialize to bytes for storage / transmission. Uses bincode
    /// over the explicit byte representation so cross-version
    /// (de)serializers can be implemented without touching pqcrypto's
    /// opaque types directly.
    pub fn to_bytes(&self) -> Vec<u8> {
        let wire = WireIdentityKey::from(self);
        bincode::serialize(&wire).expect("identity key bincode infallible")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let wire: WireIdentityKey =
            bincode::deserialize(bytes).context("decode identity key wire bytes")?;
        Self::try_from(wire)
    }

    /// 8-byte fingerprint suitable for human-readable display.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.classical_public.as_bytes());
        hasher.update(self.pq_public.as_bytes());
        let hash = hasher.finalize();
        let f = &hash.as_bytes()[..8];
        format!(
            "{:02X}{:02X} {:02X}{:02X} {:02X}{:02X} {:02X}{:02X}",
            f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
        )
    }
}

// ---------------------------------------------------------------------------
// Wire serde helpers (used by IdentityKey + HybridSignature)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WireIdentityKey {
    classical_public: [u8; 32],
    pq_public: Vec<u8>,
    identity_id: IdentityId,
    created_at: u64,
}

impl From<&IdentityKey> for WireIdentityKey {
    fn from(k: &IdentityKey) -> Self {
        WireIdentityKey {
            classical_public: k.classical_public.to_bytes(),
            pq_public: k.pq_public.as_bytes().to_vec(),
            identity_id: k.identity_id,
            created_at: k.created_at,
        }
    }
}

impl TryFrom<WireIdentityKey> for IdentityKey {
    type Error = anyhow::Error;

    fn try_from(w: WireIdentityKey) -> Result<Self> {
        let classical_public = VerifyingKey::from_bytes(&w.classical_public)
            .map_err(|e| anyhow!("invalid Ed25519 pub: {e}"))?;
        let pq_public = dilithium2::PublicKey::from_bytes(&w.pq_public)
            .map_err(|e| anyhow!("invalid PQ pub: {e}"))?;
        Ok(IdentityKey {
            classical_public,
            pq_public,
            identity_id: w.identity_id,
            created_at: w.created_at,
        })
    }
}

impl Serialize for IdentityKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        WireIdentityKey::from(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for IdentityKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = WireIdentityKey::deserialize(d)?;
        IdentityKey::try_from(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct WireHybridSignature {
    /// Ed25519 signature serialised as a Vec — serde's stable derive
    /// for fixed-size arrays only covers up to length 32, so we go
    /// through a Vec on the wire to keep this version-portable.
    classical_signature: Vec<u8>,
    pq_signature: Vec<u8>,
    signer_identity: IdentityId,
    timestamp: u64,
}

impl Serialize for HybridSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        WireHybridSignature {
            classical_signature: self.classical_signature.to_bytes().to_vec(),
            pq_signature: self.pq_signature.as_bytes().to_vec(),
            signer_identity: self.signer_identity,
            timestamp: self.timestamp,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for HybridSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = WireHybridSignature::deserialize(d)?;
        if wire.classical_signature.len() != 64 {
            return Err(serde::de::Error::custom(
                "classical_signature must be 64 bytes",
            ));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&wire.classical_signature);
        let classical_signature = Signature::from_bytes(&sig_bytes);
        let pq_signature =
            dilithium2::DetachedSignature::from_bytes(&wire.pq_signature)
                .map_err(serde::de::Error::custom)?;
        Ok(HybridSignature {
            classical_signature,
            pq_signature,
            signer_identity: wire.signer_identity,
            timestamp: wire.timestamp,
        })
    }
}

// ---------------------------------------------------------------------------
// DeviceKey
// ---------------------------------------------------------------------------

pub struct DeviceKey {
    x25519_private_bytes: [u8; 32],
    x25519_public: x25519_dalek::PublicKey,
    kyber_private_bytes: Vec<u8>,
    kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    device_id: DeviceId,
    identity_id: IdentityId,
    created_at: u64,
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        self.x25519_private_bytes.zeroize();
        self.kyber_private_bytes.zeroize();
    }
}

impl DeviceKey {
    pub fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey {
            x25519_public: self.x25519_public,
            kyber_public: self.kyber_public.clone(),
            device_id: self.device_id,
            identity_id: self.identity_id,
            created_at: self.created_at,
        }
    }

    pub fn x25519_agree(&self, other_public: &x25519_dalek::PublicKey) -> [u8; 32] {
        let sk = x25519_dalek::StaticSecret::from(self.x25519_private_bytes);
        sk.diffie_hellman(other_public).to_bytes()
    }

    pub fn kyber_encapsulate(
        &self,
        other_public: &pqcrypto_kyber::kyber768::PublicKey,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
        let (shared_secret, ciphertext) = pqcrypto_kyber::kyber768::encapsulate(other_public);
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&shared_secret.as_bytes()[..32]);
        Ok((ciphertext.as_bytes().to_vec(), ss))
    }

    pub fn kyber_decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|e| anyhow!("Invalid Kyber ciphertext: {e}"))?;
        let sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(&self.kyber_private_bytes)
            .map_err(|e| anyhow!("Invalid persisted Kyber sk: {e}"))?;
        let shared = pqcrypto_kyber::kyber768::decapsulate(&ct, &sk);
        let mut ss = [0u8; 32];
        ss.copy_from_slice(&shared.as_bytes()[..32]);
        Ok(ss)
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn identity_id(&self) -> IdentityId {
        self.identity_id
    }
}

// ---------------------------------------------------------------------------
// Display / conversions
// ---------------------------------------------------------------------------

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
    fn keypair_round_trip_through_keystore_bytes() {
        let kp = IdentityKeyPair::generate().unwrap();
        let bytes = kp.serialize_for_keystore().unwrap();
        let kp2 = IdentityKeyPair::deserialize_from_keystore(&bytes).unwrap();
        assert_eq!(kp.identity_id(), kp2.identity_id());

        let msg = b"hello";
        let sig = kp.sign(msg).unwrap();
        let pub_ = kp2.public_key();
        assert!(pub_.verify(msg, &sig).unwrap());
    }

    #[test]
    fn identity_key_round_trip_through_serde() {
        let kp = IdentityKeyPair::generate().unwrap();
        let pk = kp.public_key();
        let bytes = pk.to_bytes();
        let pk2 = IdentityKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.identity_id, pk2.identity_id);
        assert_eq!(pk.classical_public, pk2.classical_public);
        assert_eq!(pk.pq_public.as_bytes(), pk2.pq_public.as_bytes());
    }

    #[test]
    fn fingerprint_format() {
        let kp = IdentityKeyPair::generate().unwrap();
        let fp = kp.public_key().fingerprint();
        assert_eq!(fp.len(), 19); // "XXXX XXXX XXXX XXXX"
    }
}
