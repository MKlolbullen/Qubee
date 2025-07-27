use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret};
use serde::{Serialize, Deserialize};
use blake3::Hasher;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::identity_key::{IdentityKey, IdentityKeyPair, DeviceKey, DevicePublicKey, IdentityId, DeviceId, HybridSignature};
use crate::crypto::enhanced_ratchet::EnhancedHybridRatchet;
use crate::security::secure_rng;

/// Signal Protocol-inspired key distribution system
pub struct SignalProtocol {
    identity_keypair: IdentityKeyPair,
    device_key: DeviceKey,
    signed_prekeys: HashMap<u32, SignedPreKey>,
    one_time_prekeys: HashMap<u32, OneTimePreKey>,
    next_prekey_id: u32,
}

/// Signed pre-key for key exchange initialization
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub id: u32,
    pub device_public_key: DevicePublicKey,
    pub signature: HybridSignature,
    pub created_at: u64,
}

/// One-time pre-key for perfect forward secrecy
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    pub x25519_public: x25519_dalek::PublicKey,
    pub kyber_public: pqcrypto_kyber::kyber768::PublicKey,
    pub created_at: u64,
}

/// Bundle of keys for initiating communication
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: IdentityKey,
    pub device_id: DeviceId,
    pub signed_prekey: SignedPreKey,
    pub one_time_prekey: Option<OneTimePreKey>,
    pub bundle_timestamp: u64,
}

/// Result of key exchange initialization
pub struct KeyExchangeResult {
    pub shared_secret: [u8; 64], // Combined classical + post-quantum secret
    pub ratchet: EnhancedHybridRatchet,
    pub used_one_time_key: Option<u32>,
}

/// Key distribution server interface
pub trait KeyDistributionServer {
    fn upload_prekey_bundle(&mut self, bundle: &PreKeyBundle) -> Result<()>;
    fn get_prekey_bundle(&self, identity_id: &IdentityId, device_id: &DeviceId) -> Result<PreKeyBundle>;
    fn remove_one_time_prekey(&mut self, identity_id: &IdentityId, device_id: &DeviceId, prekey_id: u32) -> Result<()>;
    fn list_devices(&self, identity_id: &IdentityId) -> Result<Vec<DeviceId>>;
}

/// In-memory key distribution server for testing
pub struct InMemoryKeyServer {
    bundles: HashMap<(IdentityId, DeviceId), PreKeyBundle>,
}

impl SignalProtocol {
    /// Create a new Signal Protocol instance
    pub fn new(identity_keypair: IdentityKeyPair, device_info: &[u8]) -> Result<Self> {
        let device_key = identity_keypair.derive_device_key(device_info)?;
        
        Ok(SignalProtocol {
            identity_keypair,
            device_key,
            signed_prekeys: HashMap::new(),
            one_time_prekeys: HashMap::new(),
            next_prekey_id: 1,
        })
    }
    
    /// Generate and store a new signed pre-key
    pub fn generate_signed_prekey(&mut self) -> Result<SignedPreKey> {
        let prekey_id = self.next_prekey_id;
        self.next_prekey_id += 1;
        
        let device_public_key = self.device_key.public_key();
        
        // Sign the device public key with identity key
        let signature_data = self.serialize_device_key_for_signing(&device_public_key)?;
        let signature = self.identity_keypair.sign(&signature_data)?;
        
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let signed_prekey = SignedPreKey {
            id: prekey_id,
            device_public_key,
            signature,
            created_at,
        };
        
        self.signed_prekeys.insert(prekey_id, signed_prekey.clone());
        
        Ok(signed_prekey)
    }
    
    /// Generate multiple one-time pre-keys
    pub fn generate_one_time_prekeys(&mut self, count: usize) -> Result<Vec<OneTimePreKey>> {
        let mut prekeys = Vec::new();
        
        for _ in 0..count {
            let prekey_id = self.next_prekey_id;
            self.next_prekey_id += 1;
            
            // Generate ephemeral X25519 key pair
            let x25519_private = x25519_dalek::StaticSecret::new(&mut rand::thread_rng());
            let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);
            
            // Generate ephemeral Kyber key pair
            let (kyber_public, _kyber_private) = pqcrypto_kyber::kyber768::keypair();
            
            let created_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();
            
            let one_time_prekey = OneTimePreKey {
                id: prekey_id,
                x25519_public,
                kyber_public,
                created_at,
            };
            
            self.one_time_prekeys.insert(prekey_id, one_time_prekey.clone());
            prekeys.push(one_time_prekey);
        }
        
        Ok(prekeys)
    }
    
    /// Create a pre-key bundle for upload to the server
    pub fn create_prekey_bundle(&self) -> Result<PreKeyBundle> {
        // Get the most recent signed pre-key
        let signed_prekey = self.signed_prekeys
            .values()
            .max_by_key(|pk| pk.created_at)
            .ok_or_else(|| anyhow::anyhow!("No signed pre-keys available"))?
            .clone();
        
        // Get a random one-time pre-key
        let one_time_prekey = self.one_time_prekeys
            .values()
            .next()
            .cloned();
        
        let bundle_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        Ok(PreKeyBundle {
            identity_key: self.identity_keypair.public_key(),
            device_id: self.device_key.device_id(),
            signed_prekey,
            one_time_prekey,
            bundle_timestamp,
        })
    }
    
    /// Initiate key exchange with another user
    pub fn initiate_key_exchange(
        &self,
        remote_bundle: &PreKeyBundle,
    ) -> Result<KeyExchangeResult> {
        // Verify the signed pre-key signature
        self.verify_prekey_bundle(remote_bundle)?;
        
        // Perform triple Diffie-Hellman (3DH) key exchange
        let shared_secrets = self.perform_3dh_key_exchange(remote_bundle)?;
        
        // Combine classical and post-quantum shared secrets
        let combined_secret = self.combine_shared_secrets(&shared_secrets)?;
        
        // Initialize the double ratchet
        let mut ratchet = EnhancedHybridRatchet::new()?;
        ratchet.initialize_sender(&combined_secret, &self.device_key.public_key())?;
        
        Ok(KeyExchangeResult {
            shared_secret: combined_secret,
            ratchet,
            used_one_time_key: remote_bundle.one_time_prekey.as_ref().map(|otk| otk.id),
        })
    }
    
    /// Respond to key exchange initiation
    pub fn respond_to_key_exchange(
        &self,
        initiator_identity: &IdentityKey,
        initiator_device: &DevicePublicKey,
        used_one_time_key: Option<u32>,
    ) -> Result<KeyExchangeResult> {
        // Verify initiator's identity and device key
        self.verify_device_key(initiator_identity, initiator_device)?;
        
        // Reconstruct the key exchange
        let shared_secrets = self.reconstruct_3dh_key_exchange(
            initiator_device,
            used_one_time_key,
        )?;
        
        // Combine shared secrets
        let combined_secret = self.combine_shared_secrets(&shared_secrets)?;
        
        // Initialize the double ratchet as receiver
        let mut ratchet = EnhancedHybridRatchet::new()?;
        ratchet.initialize_receiver(&combined_secret, initiator_device)?;
        
        // Remove used one-time pre-key
        if let Some(otk_id) = used_one_time_key {
            self.one_time_prekeys.remove(&otk_id);
        }
        
        Ok(KeyExchangeResult {
            shared_secret: combined_secret,
            ratchet,
            used_one_time_key,
        })
    }
    
    /// Verify a pre-key bundle's authenticity
    fn verify_prekey_bundle(&self, bundle: &PreKeyBundle) -> Result<()> {
        // Verify signed pre-key signature
        let signature_data = self.serialize_device_key_for_signing(&bundle.signed_prekey.device_public_key)?;
        
        let signature_valid = bundle.identity_key.verify(&signature_data, &bundle.signed_prekey.signature)?;
        if !signature_valid {
            return Err(anyhow::anyhow!("Invalid signed pre-key signature"));
        }
        
        // Verify device key belongs to the identity
        if bundle.signed_prekey.device_public_key.identity_id != bundle.identity_key.identity_id {
            return Err(anyhow::anyhow!("Device key identity mismatch"));
        }
        
        // Check bundle freshness (within 7 days)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        if current_time.saturating_sub(bundle.bundle_timestamp) > 7 * 24 * 3600 {
            return Err(anyhow::anyhow!("Pre-key bundle is too old"));
        }
        
        Ok(())
    }
    
    /// Verify a device key belongs to an identity
    fn verify_device_key(&self, identity: &IdentityKey, device_key: &DevicePublicKey) -> Result<()> {
        if device_key.identity_id != identity.identity_id {
            return Err(anyhow::anyhow!("Device key identity mismatch"));
        }
        
        // Additional verification could include checking device key derivation
        // This would require the identity key holder to provide a proof
        
        Ok(())
    }
    
    /// Perform triple Diffie-Hellman key exchange
    fn perform_3dh_key_exchange(&self, remote_bundle: &PreKeyBundle) -> Result<SharedSecrets> {
        let remote_device = &remote_bundle.signed_prekey.device_public_key;
        
        // DH1: Our identity key with their signed pre-key
        let dh1_classical = self.device_key.x25519_agree(&remote_device.x25519_public);
        let (dh1_pq_ct, dh1_pq_ss) = self.device_key.kyber_encapsulate(&remote_device.kyber_public)?;
        
        // DH2: Our ephemeral key with their identity key (via device key)
        let dh2_classical = self.device_key.x25519_agree(&remote_device.x25519_public);
        let (dh2_pq_ct, dh2_pq_ss) = self.device_key.kyber_encapsulate(&remote_device.kyber_public)?;
        
        // DH3: Our ephemeral key with their one-time pre-key (if available)
        let (dh3_classical, dh3_pq_ss, dh3_pq_ct) = if let Some(otk) = &remote_bundle.one_time_prekey {
            let dh3_classical = self.device_key.x25519_agree(&otk.x25519_public);
            let (dh3_pq_ct, dh3_pq_ss) = self.device_key.kyber_encapsulate(&otk.kyber_public)?;
            (Some(dh3_classical), Some(dh3_pq_ss), Some(dh3_pq_ct))
        } else {
            (None, None, None)
        };
        
        Ok(SharedSecrets {
            dh1_classical,
            dh1_pq_ss,
            dh1_pq_ct,
            dh2_classical,
            dh2_pq_ss,
            dh2_pq_ct,
            dh3_classical,
            dh3_pq_ss,
            dh3_pq_ct,
        })
    }
    
    /// Reconstruct key exchange from the receiver's perspective
    fn reconstruct_3dh_key_exchange(
        &self,
        initiator_device: &DevicePublicKey,
        used_one_time_key: Option<u32>,
    ) -> Result<SharedSecrets> {
        // DH1: Their identity key with our signed pre-key
        let dh1_classical = self.device_key.x25519_agree(&initiator_device.x25519_public);
        // Note: For PQ, we need the ciphertext from the initiator to decapsulate
        // This is simplified - in practice, the ciphertext would be transmitted
        let dh1_pq_ss = [0u8; 32]; // Placeholder
        let dh1_pq_ct = Vec::new(); // Placeholder
        
        // DH2: Their ephemeral key with our identity key
        let dh2_classical = self.device_key.x25519_agree(&initiator_device.x25519_public);
        let dh2_pq_ss = [0u8; 32]; // Placeholder
        let dh2_pq_ct = Vec::new(); // Placeholder
        
        // DH3: Their ephemeral key with our one-time pre-key
        let (dh3_classical, dh3_pq_ss, dh3_pq_ct) = if let Some(otk_id) = used_one_time_key {
            if let Some(_otk) = self.one_time_prekeys.get(&otk_id) {
                // In practice, we would use the one-time pre-key private key
                let dh3_classical = self.device_key.x25519_agree(&initiator_device.x25519_public);
                let dh3_pq_ss = [0u8; 32]; // Placeholder
                let dh3_pq_ct = Vec::new(); // Placeholder
                (Some(dh3_classical), Some(dh3_pq_ss), Some(dh3_pq_ct))
            } else {
                return Err(anyhow::anyhow!("One-time pre-key not found"));
            }
        } else {
            (None, None, None)
        };
        
        Ok(SharedSecrets {
            dh1_classical,
            dh1_pq_ss,
            dh1_pq_ct,
            dh2_classical,
            dh2_pq_ss,
            dh2_pq_ct,
            dh3_classical,
            dh3_pq_ss,
            dh3_pq_ct,
        })
    }
    
    /// Combine multiple shared secrets into a single master secret
    fn combine_shared_secrets(&self, secrets: &SharedSecrets) -> Result<[u8; 64]> {
        let mut hasher = Hasher::new();
        
        // Add classical shared secrets
        hasher.update(&secrets.dh1_classical);
        hasher.update(&secrets.dh2_classical);
        if let Some(dh3) = &secrets.dh3_classical {
            hasher.update(dh3);
        }
        
        // Add post-quantum shared secrets
        hasher.update(&secrets.dh1_pq_ss);
        hasher.update(&secrets.dh2_pq_ss);
        if let Some(dh3_pq) = &secrets.dh3_pq_ss {
            hasher.update(dh3_pq);
        }
        
        // Add domain separator
        hasher.update(b"qubee_signal_kdf");
        
        let hash = hasher.finalize();
        
        // Expand to 64 bytes using HKDF-like construction
        let mut output = [0u8; 64];
        output[..32].copy_from_slice(&hash.as_bytes()[..32]);
        
        // Second round for remaining bytes
        let mut hasher2 = Hasher::new();
        hasher2.update(&hash.as_bytes());
        hasher2.update(&[0x01]);
        let hash2 = hasher2.finalize();
        output[32..].copy_from_slice(&hash2.as_bytes()[..32]);
        
        Ok(output)
    }
    
    /// Serialize device key for signing
    fn serialize_device_key_for_signing(&self, device_key: &DevicePublicKey) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(device_key.x25519_public.as_bytes());
        data.extend_from_slice(device_key.kyber_public.as_bytes());
        data.extend_from_slice(device_key.device_id.as_ref());
        data.extend_from_slice(device_key.identity_id.as_ref());
        data.extend_from_slice(&device_key.created_at.to_le_bytes());
        Ok(data)
    }
    
    /// Get identity key pair
    pub fn identity_keypair(&self) -> &IdentityKeyPair {
        &self.identity_keypair
    }
    
    /// Get device key
    pub fn device_key(&self) -> &DeviceKey {
        &self.device_key
    }
    
    /// Get current signed pre-keys
    pub fn signed_prekeys(&self) -> &HashMap<u32, SignedPreKey> {
        &self.signed_prekeys
    }
    
    /// Get current one-time pre-keys
    pub fn one_time_prekeys(&self) -> &HashMap<u32, OneTimePreKey> {
        &self.one_time_prekeys
    }
}

/// Shared secrets from key exchange
struct SharedSecrets {
    dh1_classical: [u8; 32],
    dh1_pq_ss: [u8; 32],
    dh1_pq_ct: Vec<u8>,
    dh2_classical: [u8; 32],
    dh2_pq_ss: [u8; 32],
    dh2_pq_ct: Vec<u8>,
    dh3_classical: Option<[u8; 32]>,
    dh3_pq_ss: Option<[u8; 32]>,
    dh3_pq_ct: Option<Vec<u8>>,
}

impl InMemoryKeyServer {
    /// Create a new in-memory key server
    pub fn new() -> Self {
        InMemoryKeyServer {
            bundles: HashMap::new(),
        }
    }
}

impl KeyDistributionServer for InMemoryKeyServer {
    fn upload_prekey_bundle(&mut self, bundle: &PreKeyBundle) -> Result<()> {
        let key = (bundle.identity_key.identity_id, bundle.device_id);
        self.bundles.insert(key, bundle.clone());
        Ok(())
    }
    
    fn get_prekey_bundle(&self, identity_id: &IdentityId, device_id: &DeviceId) -> Result<PreKeyBundle> {
        let key = (*identity_id, *device_id);
        self.bundles
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Pre-key bundle not found"))
    }
    
    fn remove_one_time_prekey(&mut self, identity_id: &IdentityId, device_id: &DeviceId, prekey_id: u32) -> Result<()> {
        let key = (*identity_id, *device_id);
        if let Some(bundle) = self.bundles.get_mut(&key) {
            if let Some(ref otk) = bundle.one_time_prekey {
                if otk.id == prekey_id {
                    bundle.one_time_prekey = None;
                }
            }
        }
        Ok(())
    }
    
    fn list_devices(&self, identity_id: &IdentityId) -> Result<Vec<DeviceId>> {
        let devices: Vec<DeviceId> = self.bundles
            .keys()
            .filter(|(id, _)| id == identity_id)
            .map(|(_, device_id)| *device_id)
            .collect();
        
        Ok(devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signal_protocol_initialization() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let device_info = b"test_device";
        
        let mut signal_protocol = SignalProtocol::new(identity_keypair, device_info)
            .expect("Should create Signal protocol");
        
        // Generate signed pre-key
        let signed_prekey = signal_protocol.generate_signed_prekey()
            .expect("Should generate signed pre-key");
        
        assert_eq!(signed_prekey.id, 1);
        assert_eq!(signed_prekey.device_public_key.identity_id, signal_protocol.identity_keypair.identity_id());
        
        // Generate one-time pre-keys
        let one_time_prekeys = signal_protocol.generate_one_time_prekeys(10)
            .expect("Should generate one-time pre-keys");
        
        assert_eq!(one_time_prekeys.len(), 10);
    }
    
    #[test]
    fn test_prekey_bundle_creation_and_verification() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let device_info = b"test_device";
        
        let mut signal_protocol = SignalProtocol::new(identity_keypair, device_info)
            .expect("Should create Signal protocol");
        
        // Generate keys
        signal_protocol.generate_signed_prekey().expect("Should generate signed pre-key");
        signal_protocol.generate_one_time_prekeys(5).expect("Should generate one-time pre-keys");
        
        // Create bundle
        let bundle = signal_protocol.create_prekey_bundle()
            .expect("Should create pre-key bundle");
        
        // Verify bundle
        signal_protocol.verify_prekey_bundle(&bundle)
            .expect("Should verify pre-key bundle");
    }
    
    #[test]
    fn test_key_distribution_server() {
        let identity_keypair = IdentityKeyPair::generate().expect("Should generate keypair");
        let device_info = b"test_device";
        
        let mut signal_protocol = SignalProtocol::new(identity_keypair, device_info)
            .expect("Should create Signal protocol");
        
        signal_protocol.generate_signed_prekey().expect("Should generate signed pre-key");
        signal_protocol.generate_one_time_prekeys(5).expect("Should generate one-time pre-keys");
        
        let bundle = signal_protocol.create_prekey_bundle()
            .expect("Should create pre-key bundle");
        
        // Test server operations
        let mut server = InMemoryKeyServer::new();
        
        server.upload_prekey_bundle(&bundle)
            .expect("Should upload bundle");
        
        let retrieved_bundle = server.get_prekey_bundle(&bundle.identity_key.identity_id, &bundle.device_id)
            .expect("Should retrieve bundle");
        
        assert_eq!(bundle.identity_key.identity_id, retrieved_bundle.identity_key.identity_id);
        assert_eq!(bundle.device_id, retrieved_bundle.device_id);
        
        let devices = server.list_devices(&bundle.identity_key.identity_id)
            .expect("Should list devices");
        
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0], bundle.device_id);
    }
    
    #[test]
    fn test_key_exchange_flow() {
        // Create two users
        let alice_identity = IdentityKeyPair::generate().expect("Should generate Alice's keypair");
        let bob_identity = IdentityKeyPair::generate().expect("Should generate Bob's keypair");
        
        let mut alice_protocol = SignalProtocol::new(alice_identity, b"alice_device")
            .expect("Should create Alice's protocol");
        let mut bob_protocol = SignalProtocol::new(bob_identity, b"bob_device")
            .expect("Should create Bob's protocol");
        
        // Generate keys
        alice_protocol.generate_signed_prekey().expect("Should generate Alice's signed pre-key");
        alice_protocol.generate_one_time_prekeys(5).expect("Should generate Alice's one-time pre-keys");
        
        bob_protocol.generate_signed_prekey().expect("Should generate Bob's signed pre-key");
        bob_protocol.generate_one_time_prekeys(5).expect("Should generate Bob's one-time pre-keys");
        
        // Create bundles
        let alice_bundle = alice_protocol.create_prekey_bundle()
            .expect("Should create Alice's bundle");
        let bob_bundle = bob_protocol.create_prekey_bundle()
            .expect("Should create Bob's bundle");
        
        // Alice initiates key exchange with Bob
        let alice_result = alice_protocol.initiate_key_exchange(&bob_bundle)
            .expect("Should initiate key exchange");
        
        // Bob responds to Alice's key exchange
        let bob_result = bob_protocol.respond_to_key_exchange(
            &alice_bundle.identity_key,
            &alice_bundle.signed_prekey.device_public_key,
            alice_result.used_one_time_key,
        ).expect("Should respond to key exchange");
        
        // Both should have the same shared secret
        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
    }
}
