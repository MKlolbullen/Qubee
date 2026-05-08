use anyhow::Result;
use serde::{Serialize, Deserialize};
use blake3::Hasher;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::identity_key::{IdentityKey, IdentityKeyPair, DeviceKey, DevicePublicKey, IdentityId, DeviceId, HybridSignature};
use crate::crypto::enhanced_ratchet::EnhancedHybridRatchet;

/// Signal Protocol-inspired key distribution system
pub struct SignalProtocol {
    identity_keypair: IdentityKeyPair,
    device_key: DeviceKey,
    signed_prekeys: HashMap<u32, SignedPreKey>,
    one_time_prekeys: HashMap<u32, OneTimePreKey>,
    /// Private halves of the one-time pre-keys, kept separate from
    /// the public bundle so `OneTimePreKey`'s Serialize/Deserialize
    /// derives don't accidentally leak secret material onto the wire.
    /// Keyed by the same id as `one_time_prekeys`.
    one_time_prekey_secrets: HashMap<u32, OneTimePreKeySecrets>,
    next_prekey_id: u32,
}

/// Secret half of a one-time pre-key. Lives only in the local
/// `SignalProtocol` instance; never serialised, never sent.
struct OneTimePreKeySecrets {
    x25519_private: x25519_dalek::StaticSecret,
    /// ML-KEM-768 secret key bytes. Stored as opaque bytes (rather
    /// than the typed `pqcrypto_mlkem::mlkem768::SecretKey`) so this
    /// struct doesn't need to know how to serde-derive across
    /// pqcrypto types.
    kyber_private_bytes: Vec<u8>,
}

/// Signed pre-key for key exchange initialization
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub id: u32,
    pub device_public_key: DevicePublicKey,
    pub signature: HybridSignature,
    pub created_at: u64,
}

/// One-time pre-key for perfect forward secrecy. Public-only; the
/// matching secret halves live in
/// `SignalProtocol::one_time_prekey_secrets`.
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub id: u32,
    pub x25519_public: x25519_dalek::PublicKey,
    pub kyber_public: pqcrypto_mlkem::mlkem768::PublicKey,
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
    /// ML-KEM ciphertexts the initiator must transmit alongside the
    /// handshake so the responder can decapsulate the matching shared
    /// secrets. Without these the responder has no way to recover
    /// `dh{1,2,3}_pq_ss` — the previous shape silently dropped these
    /// on the floor and the responder substituted `[0u8; 32]`
    /// placeholders, producing a master secret that didn't match.
    pub kyber_ciphertexts: HandshakeCiphertexts,
}

/// ML-KEM-768 ciphertexts produced by the initiator during the X3DH
/// handshake. Carried out-of-band (Signal stores these in the
/// initial message envelope) so the responder can recover each
/// `dh*_pq_ss`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeCiphertexts {
    /// Ciphertext for DH1: encapsulated against the responder's
    /// device Kyber public key (carried in the signed-prekey
    /// bundle).
    pub dh1: Vec<u8>,
    /// Ciphertext for DH2: same target as DH1 in this prototype.
    /// (See module-level note about DH1==DH2 symmetry — separate
    /// fix.)
    pub dh2: Vec<u8>,
    /// Ciphertext for DH3, present iff the bundle carried a
    /// one-time pre-key. Encapsulated against the OTK's Kyber
    /// public key.
    pub dh3: Option<Vec<u8>>,
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
            one_time_prekey_secrets: HashMap::new(),
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

            // Generate ephemeral X25519 key pair. Keep the private
            // half — earlier the variable was named with a leading
            // underscore and dropped on the floor, which made any
            // later DH agreement structurally impossible.
            let x25519_private = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
            let x25519_public = x25519_dalek::PublicKey::from(&x25519_private);

            // Generate an ML-KEM-768 (FIPS 203 Kyber-768) keypair.
            // Same fix as above: store the secret bytes so the
            // responder side can actually decapsulate the matching
            // ciphertext later.
            let (kyber_public, kyber_private) = pqcrypto_mlkem::mlkem768::keypair();
            let kyber_private_bytes = kyber_private.as_bytes().to_vec();

            let created_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();

            let one_time_prekey = OneTimePreKey {
                id: prekey_id,
                x25519_public,
                kyber_public,
                created_at,
            };

            self.one_time_prekey_secrets.insert(
                prekey_id,
                OneTimePreKeySecrets {
                    x25519_private,
                    kyber_private_bytes,
                },
            );
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
            kyber_ciphertexts: HandshakeCiphertexts {
                dh1: shared_secrets.dh1_pq_ct.clone(),
                dh2: shared_secrets.dh2_pq_ct.clone(),
                dh3: shared_secrets.dh3_pq_ct.clone(),
            },
        })
    }
    
    /// Respond to key exchange initiation. Takes the ML-KEM
    /// ciphertexts the initiator transmitted alongside the
    /// handshake; without them DH{1,2,3}_pq can't be recovered.
    /// `&mut self` so the consumed one-time pre-key (and its secret
    /// half) can be evicted in the same call.
    pub fn respond_to_key_exchange(
        &mut self,
        initiator_identity: &IdentityKey,
        initiator_device: &DevicePublicKey,
        ciphertexts: &HandshakeCiphertexts,
        used_one_time_key: Option<u32>,
    ) -> Result<KeyExchangeResult> {
        // Verify initiator's identity and device key
        self.verify_device_key(initiator_identity, initiator_device)?;

        // Reconstruct the key exchange
        let shared_secrets = self.reconstruct_3dh_key_exchange(
            initiator_device,
            ciphertexts,
            used_one_time_key,
        )?;

        // Combine shared secrets
        let combined_secret = self.combine_shared_secrets(&shared_secrets)?;

        // Initialize the double ratchet as receiver
        let mut ratchet = EnhancedHybridRatchet::new()?;
        ratchet.initialize_receiver(&combined_secret, initiator_device)?;

        // Evict the consumed one-time pre-key (and its secret half).
        // Per X3DH this prekey must be single-use; leaving it around
        // weakens forward secrecy.
        if let Some(otk_id) = used_one_time_key {
            self.one_time_prekeys.remove(&otk_id);
            self.one_time_prekey_secrets.remove(&otk_id);
        }

        Ok(KeyExchangeResult {
            shared_secret: combined_secret,
            ratchet,
            used_one_time_key,
            // Responder doesn't produce ciphertexts of its own under
            // X3DH — it only consumes the initiator's. Echo them
            // back so the result type is uniform; callers on this
            // side can ignore the field.
            kyber_ciphertexts: ciphertexts.clone(),
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
    
    /// Reconstruct shared secrets from the responder's perspective.
    ///
    /// DH1 and DH2 decapsulate the initiator's ciphertexts against
    /// our long-lived device Kyber secret (held inside `DeviceKey`).
    /// DH3, when the initiator used a one-time pre-key, decapsulates
    /// against the matching OTK secret we stashed in
    /// `one_time_prekey_secrets`.
    ///
    /// Note on DH1==DH2: the X25519 halves on this branch both run
    /// `device_key.x25519_agree(&initiator_device.x25519_public)`,
    /// producing the same value twice. That's a structural defect in
    /// the prototype's 3DH layout (the initiator should have an
    /// ephemeral keypair binding DH2/DH3 separately from DH1) and
    /// affects both peers symmetrically. Out of scope for this
    /// commit — fixing it requires adding an ephemeral key field to
    /// the handshake envelope on the initiator side.
    fn reconstruct_3dh_key_exchange(
        &self,
        initiator_device: &DevicePublicKey,
        ciphertexts: &HandshakeCiphertexts,
        used_one_time_key: Option<u32>,
    ) -> Result<SharedSecrets> {
        // DH1 — classical leg + ML-KEM decapsulation against our
        // device Kyber secret.
        let dh1_classical = self.device_key.x25519_agree(&initiator_device.x25519_public);
        let dh1_pq_ss = self
            .device_key
            .kyber_decapsulate(&ciphertexts.dh1)?;
        let dh1_pq_ct = ciphertexts.dh1.clone();

        // DH2 — same target as DH1 today (see method-level note).
        let dh2_classical = self.device_key.x25519_agree(&initiator_device.x25519_public);
        let dh2_pq_ss = self
            .device_key
            .kyber_decapsulate(&ciphertexts.dh2)?;
        let dh2_pq_ct = ciphertexts.dh2.clone();

        // DH3 — present iff a one-time pre-key was used. The
        // initiator must have included the matching ML-KEM
        // ciphertext for us to decapsulate against the OTK secret
        // we stashed when we generated the prekey.
        let (dh3_classical, dh3_pq_ss, dh3_pq_ct) = match used_one_time_key {
            Some(otk_id) => {
                let secrets = self
                    .one_time_prekey_secrets
                    .get(&otk_id)
                    .ok_or_else(|| anyhow::anyhow!(
                        "one-time pre-key {otk_id} secret missing — \
                         either already consumed or never generated locally"
                    ))?;
                let dh3_ct = ciphertexts.dh3.as_ref().ok_or_else(|| anyhow::anyhow!(
                    "initiator referenced one-time pre-key {otk_id} but \
                     omitted its ML-KEM ciphertext"
                ))?;
                let dh3_classical =
                    secrets.x25519_private.diffie_hellman(&initiator_device.x25519_public).to_bytes();
                let sk = pqcrypto_mlkem::mlkem768::SecretKey::from_bytes(&secrets.kyber_private_bytes)
                    .map_err(|e| anyhow::anyhow!("invalid stored OTK secret: {e}"))?;
                let ct = pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(dh3_ct)
                    .map_err(|e| anyhow::anyhow!("invalid DH3 ciphertext: {e}"))?;
                let shared = pqcrypto_mlkem::mlkem768::decapsulate(&ct, &sk);
                let mut dh3_pq_ss = [0u8; 32];
                use pqcrypto_traits::kem::SharedSecret as _;
                dh3_pq_ss.copy_from_slice(&shared.as_bytes()[..32]);
                (Some(dh3_classical), Some(dh3_pq_ss), Some(dh3_ct.clone()))
            }
            None => (None, None, None),
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
        hasher2.update(hash.as_bytes());
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