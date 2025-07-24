use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret, Zeroize};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium2;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use crate::security::secure_rng;

/// Enhanced hybrid double ratchet with post-quantum security
/// and protection against various attacks
#[derive(ZeroizeOnDrop)]
pub struct EnhancedHybridRatchet {
    // Root key for key derivation
    root_key: Secret<[u8; 32]>,
    
    // Classical DH ratchet state
    dh_send_key: Option<StaticSecret>,
    dh_recv_key: Option<X25519PublicKey>,
    
    // Post-quantum KEM ratchet state
    pq_send_key: Option<Secret<kyber768::SecretKey>>,
    pq_recv_key: Option<kyber768::PublicKey>,
    
    // Chain keys for sending and receiving
    send_chain_key: Option<Secret<[u8; 32]>>,
    recv_chain_key: Option<Secret<[u8; 32]>>,
    
    // Message counters for replay protection
    send_counter: u64,
    recv_counter: u64,
    
    // Skipped message keys for out-of-order delivery
    skipped_keys: HashMap<MessageId, Secret<[u8; 32]>>,
    
    // Security parameters
    #[zeroize(skip)]
    max_skip: usize,
    #[zeroize(skip)]
    max_cache: usize,
    
    // State tracking
    #[zeroize(skip)]
    state: RatchetState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetState {
    Uninitialized,
    Initialized,
    KeyExchanged,
    Active,
    Compromised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId {
    pub chain_id: u64,
    pub message_number: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RatchetMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MessageHeader {
    pub dh_public_key: Option<[u8; 32]>,
    pub pq_public_key: Option<Vec<u8>>,
    pub previous_chain_length: u64,
    pub message_number: u64,
    pub timestamp: u64,
}

impl EnhancedHybridRatchet {
    const MAX_SKIP_DEFAULT: usize = 1000;
    const MAX_CACHE_DEFAULT: usize = 100;
    const CHAIN_KEY_CONSTANT: &'static [u8] = b"qubee_chain_key";
    const MESSAGE_KEY_CONSTANT: &'static [u8] = b"qubee_message_key";
    
    /// Create a new uninitialized ratchet
    pub fn new() -> Self {
        EnhancedHybridRatchet {
            root_key: Secret::new([0u8; 32]),
            dh_send_key: None,
            dh_recv_key: None,
            pq_send_key: None,
            pq_recv_key: None,
            send_chain_key: None,
            recv_chain_key: None,
            send_counter: 0,
            recv_counter: 0,
            skipped_keys: HashMap::new(),
            max_skip: Self::MAX_SKIP_DEFAULT,
            max_cache: Self::MAX_CACHE_DEFAULT,
            state: RatchetState::Uninitialized,
        }
    }
    
    /// Initialize the ratchet as the sender (Alice)
    pub fn initialize_sender(
        &mut self,
        shared_secret: &[u8],
        remote_dh_key: &X25519PublicKey,
        remote_pq_key: &kyber768::PublicKey,
    ) -> Result<()> {
        if self.state != RatchetState::Uninitialized {
            return Err(anyhow::anyhow!("Ratchet already initialized"));
        }
        
        // Generate initial key pairs
        let dh_keypair = StaticSecret::new(&mut rand::rngs::OsRng);
        let (pq_ciphertext, pq_shared_secret) = kyber768::encapsulate(remote_pq_key);
        
        // Derive root key from shared secret
        self.derive_root_key(shared_secret)?;
        
        // Perform initial DH and PQ key exchanges
        let dh_shared = dh_keypair.diffie_hellman(remote_dh_key);
        
        // Combine classical and post-quantum shared secrets
        let combined_secret = self.combine_shared_secrets(
            dh_shared.as_bytes(),
            &pq_shared_secret.0,
        )?;
        
        // Initialize sending chain
        let (new_root_key, send_chain_key) = self.kdf_rk(
            self.root_key.expose_secret(),
            &combined_secret,
        )?;
        
        self.root_key = Secret::new(new_root_key);
        self.send_chain_key = Some(Secret::new(send_chain_key));
        self.dh_send_key = Some(dh_keypair);
        self.dh_recv_key = Some(*remote_dh_key);
        self.pq_recv_key = Some(remote_pq_key.clone());
        
        self.state = RatchetState::Initialized;
        
        Ok(())
    }
    
    /// Initialize the ratchet as the receiver (Bob)
    pub fn initialize_receiver(
        &mut self,
        shared_secret: &[u8],
        dh_keypair: StaticSecret,
        pq_keypair: kyber768::SecretKey,
    ) -> Result<()> {
        if self.state != RatchetState::Uninitialized {
            return Err(anyhow::anyhow!("Ratchet already initialized"));
        }
        
        // Derive root key from shared secret
        self.derive_root_key(shared_secret)?;
        
        self.dh_send_key = Some(dh_keypair);
        self.pq_send_key = Some(Secret::new(pq_keypair));
        
        self.state = RatchetState::Initialized;
        
        Ok(())
    }
    
    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<RatchetMessage> {
        if self.state != RatchetState::Active && self.state != RatchetState::KeyExchanged {
            return Err(anyhow::anyhow!("Ratchet not ready for encryption"));
        }
        
        // Get or derive message key
        let message_key = self.get_send_message_key()?;
        
        // Create message header
        let header = MessageHeader {
            dh_public_key: self.dh_send_key.as_ref()
                .map(|sk| sk.diffie_hellman(&X25519PublicKey::from([9u8; 32])).to_bytes()),
            pq_public_key: None, // Will be set if needed
            previous_chain_length: 0, // TODO: Track chain length
            message_number: self.send_counter,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        
        // Serialize header for AAD
        let header_bytes = bincode::serialize(&header)?;
        
        // Combine AAD
        let mut aad = Vec::new();
        aad.extend_from_slice(associated_data);
        aad.extend_from_slice(&header_bytes);
        
        // Encrypt the message
        let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key.expose_secret()));
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut payload = Vec::new();
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(plaintext);
        
        let ciphertext = cipher
            .encrypt(nonce, payload.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        // Compute MAC over header and ciphertext
        let mac = self.compute_mac(&header_bytes, &ciphertext)?;
        
        self.send_counter += 1;
        
        Ok(RatchetMessage {
            header,
            ciphertext,
            mac,
        })
    }
    
    /// Decrypt a message
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Verify MAC first
        let header_bytes = bincode::serialize(&message.header)?;
        let expected_mac = self.compute_mac(&header_bytes, &message.ciphertext)?;
        
        if !self.constant_time_eq(&message.mac, &expected_mac) {
            return Err(anyhow::anyhow!("MAC verification failed"));
        }
        
        // Check for replay attacks
        if message.header.message_number <= self.recv_counter {
            return Err(anyhow::anyhow!("Replay attack detected"));
        }
        
        // Handle out-of-order messages
        let message_id = MessageId {
            chain_id: 0, // TODO: Implement proper chain ID
            message_number: message.header.message_number,
        };
        
        let message_key = if let Some(key) = self.skipped_keys.remove(&message_id) {
            key
        } else {
            self.get_recv_message_key(message.header.message_number)?
        };
        
        // Decrypt the message
        if message.ciphertext.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        
        let nonce = Nonce::from_slice(&message.ciphertext[..12]);
        let ciphertext = &message.ciphertext[12..];
        
        let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key.expose_secret()));
        
        // Prepare AAD
        let mut aad = Vec::new();
        aad.extend_from_slice(associated_data);
        aad.extend_from_slice(&header_bytes);
        
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        // Update receive counter
        self.recv_counter = message.header.message_number;
        
        Ok(plaintext)
    }
    
    /// Perform a DH ratchet step
    pub fn dh_ratchet(&mut self, remote_public_key: &X25519PublicKey) -> Result<()> {
        // Generate new DH keypair
        let new_keypair = StaticSecret::new(&mut rand::rngs::OsRng);
        let shared_secret = new_keypair.diffie_hellman(remote_public_key);
        
        // Update root key and derive new chain key
        let (new_root_key, new_chain_key) = self.kdf_rk(
            self.root_key.expose_secret(),
            shared_secret.as_bytes(),
        )?;
        
        self.root_key = Secret::new(new_root_key);
        self.send_chain_key = Some(Secret::new(new_chain_key));
        self.dh_send_key = Some(new_keypair);
        self.dh_recv_key = Some(*remote_public_key);
        
        // Reset send counter
        self.send_counter = 0;
        
        self.state = RatchetState::Active;
        
        Ok(())
    }
    
    /// Perform a post-quantum ratchet step
    pub fn pq_ratchet(&mut self, remote_public_key: &kyber768::PublicKey) -> Result<()> {
        // Generate new PQ keypair
        let (pq_public_key, pq_secret_key) = kyber768::keypair();
        let (ciphertext, shared_secret) = kyber768::encapsulate(remote_public_key);
        
        // Update root key with PQ shared secret
        let (new_root_key, new_chain_key) = self.kdf_rk(
            self.root_key.expose_secret(),
            &shared_secret.0,
        )?;
        
        self.root_key = Secret::new(new_root_key);
        self.recv_chain_key = Some(Secret::new(new_chain_key));
        self.pq_send_key = Some(Secret::new(pq_secret_key));
        self.pq_recv_key = Some(remote_public_key.clone());
        
        Ok(())
    }
    
    /// Key derivation function for root key updates
    fn kdf_rk(&self, root_key: &[u8; 32], dh_output: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
        
        let mut new_root_key = [0u8; 32];
        let mut chain_key = [0u8; 32];
        
        hkdf.expand(b"qubee_root_key", &mut new_root_key)
            .map_err(|e| anyhow::anyhow!("Root key derivation failed: {}", e))?;
        
        hkdf.expand(b"qubee_chain_key", &mut chain_key)
            .map_err(|e| anyhow::anyhow!("Chain key derivation failed: {}", e))?;
        
        Ok((new_root_key, chain_key))
    }
    
    /// Key derivation function for chain key updates
    fn kdf_ck(&self, chain_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        let mut hasher = Hasher::new();
        hasher.update(chain_key);
        hasher.update(Self::CHAIN_KEY_CONSTANT);
        let new_chain_key_hash = hasher.finalize();
        
        let mut new_chain_key = [0u8; 32];
        new_chain_key.copy_from_slice(&new_chain_key_hash.as_bytes()[..32]);
        
        hasher = Hasher::new();
        hasher.update(chain_key);
        hasher.update(Self::MESSAGE_KEY_CONSTANT);
        let message_key_hash = hasher.finalize();
        
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&message_key_hash.as_bytes()[..32]);
        
        Ok((new_chain_key, message_key))
    }
    
    fn get_send_message_key(&mut self) -> Result<Secret<[u8; 32]>> {
        let chain_key = self.send_chain_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No send chain key"))?;
        
        let (new_chain_key, message_key) = self.kdf_ck(chain_key.expose_secret())?;
        
        self.send_chain_key = Some(Secret::new(new_chain_key));
        
        Ok(Secret::new(message_key))
    }
    
    fn get_recv_message_key(&mut self, message_number: u64) -> Result<Secret<[u8; 32]>> {
        let chain_key = self.recv_chain_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No receive chain key"))?;
        
        // Handle skipped messages
        let skip_count = message_number.saturating_sub(self.recv_counter + 1);
        if skip_count > self.max_skip as u64 {
            return Err(anyhow::anyhow!("Too many skipped messages"));
        }
        
        let mut current_chain_key = *chain_key.expose_secret();
        
        // Generate and store skipped message keys
        for i in 0..skip_count {
            let (new_chain_key, message_key) = self.kdf_ck(&current_chain_key)?;
            
            let message_id = MessageId {
                chain_id: 0, // TODO: Implement proper chain ID
                message_number: self.recv_counter + 1 + i,
            };
            
            if self.skipped_keys.len() >= self.max_cache {
                // Remove oldest skipped key
                if let Some((oldest_id, _)) = self.skipped_keys.iter().next() {
                    let oldest_id = *oldest_id;
                    self.skipped_keys.remove(&oldest_id);
                }
            }
            
            self.skipped_keys.insert(message_id, Secret::new(message_key));
            current_chain_key = new_chain_key;
        }
        
        // Generate the actual message key
        let (new_chain_key, message_key) = self.kdf_ck(&current_chain_key)?;
        
        self.recv_chain_key = Some(Secret::new(new_chain_key));
        
        Ok(Secret::new(message_key))
    }
    
    fn derive_root_key(&mut self, shared_secret: &[u8]) -> Result<()> {
        let mut hasher = Hasher::new();
        hasher.update(shared_secret);
        hasher.update(b"qubee_root_key_derivation");
        
        let hash = hasher.finalize();
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&hash.as_bytes()[..32]);
        
        self.root_key = Secret::new(root_key);
        
        Ok(())
    }
    
    fn combine_shared_secrets(&self, dh_secret: &[u8], pq_secret: &[u8]) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();
        hasher.update(dh_secret);
        hasher.update(pq_secret);
        hasher.update(b"qubee_hybrid_kdf");
        
        let hash = hasher.finalize();
        let mut combined = [0u8; 32];
        combined.copy_from_slice(&hash.as_bytes()[..32]);
        
        Ok(combined)
    }
    
    fn compute_mac(&self, header: &[u8], ciphertext: &[u8]) -> Result<[u8; 16]> {
        let mut hasher = Hasher::new();
        hasher.update(self.root_key.expose_secret());
        hasher.update(header);
        hasher.update(ciphertext);
        
        let hash = hasher.finalize();
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&hash.as_bytes()[..16]);
        
        Ok(mac)
    }
    
    fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
    
    /// Get the current ratchet state
    pub fn state(&self) -> RatchetState {
        self.state
    }
    
    /// Mark the ratchet as compromised
    pub fn mark_compromised(&mut self) {
        self.state = RatchetState::Compromised;
        
        // Clear all sensitive state
        self.root_key.zeroize();
        self.send_chain_key = None;
        self.recv_chain_key = None;
        self.skipped_keys.clear();
    }
    
    /// Check if the ratchet is in a usable state
    pub fn is_active(&self) -> bool {
        matches!(self.state, RatchetState::Active | RatchetState::KeyExchanged)
    }
}

impl Default for EnhancedHybridRatchet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ratchet_initialization() {
        let mut alice = EnhancedHybridRatchet::new();
        let mut bob = EnhancedHybridRatchet::new();
        
        assert_eq!(alice.state(), RatchetState::Uninitialized);
        assert_eq!(bob.state(), RatchetState::Uninitialized);
    }
    
    #[test]
    fn test_key_derivation() {
        let ratchet = EnhancedHybridRatchet::new();
        let root_key = [1u8; 32];
        let dh_output = [2u8; 32];
        
        let (new_root, chain_key) = ratchet.kdf_rk(&root_key, &dh_output).unwrap();
        
        // Keys should be different from inputs
        assert_ne!(new_root, root_key);
        assert_ne!(chain_key, root_key);
        assert_ne!(new_root, chain_key);
    }
    
    #[test]
    fn test_chain_key_derivation() {
        let ratchet = EnhancedHybridRatchet::new();
        let chain_key = [3u8; 32];
        
        let (new_chain, message_key) = ratchet.kdf_ck(&chain_key).unwrap();
        
        // Keys should be different
        assert_ne!(new_chain, chain_key);
        assert_ne!(message_key, chain_key);
        assert_ne!(new_chain, message_key);
    }
    
    #[test]
    fn test_shared_secret_combination() {
        let ratchet = EnhancedHybridRatchet::new();
        let dh_secret = [4u8; 32];
        let pq_secret = [5u8; 64];
        
        let combined = ratchet.combine_shared_secrets(&dh_secret, &pq_secret).unwrap();
        
        // Should produce deterministic output
        let combined2 = ratchet.combine_shared_secrets(&dh_secret, &pq_secret).unwrap();
        assert_eq!(combined, combined2);
        
        // Different inputs should produce different outputs
        let different_dh = [6u8; 32];
        let combined3 = ratchet.combine_shared_secrets(&different_dh, &pq_secret).unwrap();
        assert_ne!(combined, combined3);
    }
}
