use anyhow::{Context, Result};
use secrecy::{Secret, ExposeSecret, Zeroize};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use blake3::Hasher;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use crate::security::secure_rng;

/// Secure key storage with encryption and integrity protection
#[derive(ZeroizeOnDrop)]
pub struct SecureKeyStore {
    #[zeroize(skip)]
    storage_path: PathBuf,
    master_key: Secret<[u8; 32]>,
    #[zeroize(skip)]
    keys: HashMap<String, EncryptedKeyEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct EncryptedKeyEntry {
    encrypted_data: Vec<u8>,
    nonce: [u8; 12],
    key_type: KeyType,
    created_at: u64,
    last_accessed: u64,
    metadata: KeyMetadata,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum KeyType {
    IdentityKey,
    SigningKey,
    EncryptionKey,
    PreKey,
    EphemeralKey,
    RootKey,
    ChainKey,
    MessageKey,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyMetadata {
    pub algorithm: String,
    pub key_size: usize,
    pub usage: Vec<KeyUsage>,
    pub expiry: Option<u64>,
    pub tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum KeyUsage {
    Signing,
    Encryption,
    KeyAgreement,
    Authentication,
}

impl SecureKeyStore {
    /// Create a new secure key store
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();
        
        // Create storage directory if it doesn't exist
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create storage directory")?;
        }
        
        // Generate or load master key
        let master_key = Self::load_or_generate_master_key(&storage_path)?;
        
        let mut keystore = SecureKeyStore {
            storage_path: storage_path.clone(),
            master_key,
            keys: HashMap::new(),
        };
        
        // Load existing keys
        keystore.load_keys()?;
        
        Ok(keystore)
    }
    
    /// Store a key in the secure keystore
    pub fn store_key(
        &mut self,
        key_id: &str,
        key_data: &[u8],
        key_type: KeyType,
        metadata: KeyMetadata,
    ) -> Result<()> {
        // Validate key ID
        if key_id.is_empty() || key_id.len() > 256 {
            return Err(anyhow::anyhow!("Invalid key ID"));
        }
        
        // Generate random nonce
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the key data
        let cipher = ChaCha20Poly1305::new(self.master_key.expose_secret().into());
        let encrypted_data = cipher
            .encrypt(nonce, key_data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let entry = EncryptedKeyEntry {
            encrypted_data,
            nonce: nonce_bytes,
            key_type,
            created_at: current_time,
            last_accessed: current_time,
            metadata,
        };
        
        self.keys.insert(key_id.to_string(), entry);
        self.save_keys()?;
        
        Ok(())
    }
    
    /// Retrieve a key from the secure keystore
    pub fn retrieve_key(&mut self, key_id: &str) -> Result<Option<Secret<Vec<u8>>>> {
        let entry = match self.keys.get_mut(key_id) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        
        // Update last accessed time
        entry.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // Decrypt the key data
        let cipher = ChaCha20Poly1305::new(self.master_key.expose_secret().into());
        let nonce = Nonce::from_slice(&entry.nonce);
        
        let decrypted_data = cipher
            .decrypt(nonce, entry.encrypted_data.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        Ok(Some(Secret::new(decrypted_data)))
    }
    
    /// Delete a key from the keystore
    pub fn delete_key(&mut self, key_id: &str) -> Result<bool> {
        let removed = self.keys.remove(key_id).is_some();
        if removed {
            self.save_keys()?;
        }
        Ok(removed)
    }
    
    /// List all key IDs in the keystore
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
    
    /// Get key metadata without decrypting the key
    pub fn get_key_metadata(&self, key_id: &str) -> Option<&KeyMetadata> {
        self.keys.get(key_id).map(|entry| &entry.metadata)
    }
    
    /// Check if a key exists
    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
    
    /// Rotate the master key (re-encrypt all stored keys)
    pub fn rotate_master_key(&mut self) -> Result<()> {
        // Generate new master key
        let new_master_key = Secret::new(secure_rng::random::array::<32>()?);
        
        // Re-encrypt all keys with new master key
        let old_cipher = ChaCha20Poly1305::new(self.master_key.expose_secret().into());
        let new_cipher = ChaCha20Poly1305::new(new_master_key.expose_secret().into());
        
        for (_, entry) in self.keys.iter_mut() {
            // Decrypt with old key
            let old_nonce = Nonce::from_slice(&entry.nonce);
            let decrypted_data = old_cipher
                .decrypt(old_nonce, entry.encrypted_data.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to decrypt during rotation: {}", e))?;
            
            // Generate new nonce and encrypt with new key
            let new_nonce_bytes = secure_rng::random::array::<12>()?;
            let new_nonce = Nonce::from_slice(&new_nonce_bytes);
            
            let new_encrypted_data = new_cipher
                .encrypt(new_nonce, decrypted_data.as_ref())
                .map_err(|e| anyhow::anyhow!("Failed to encrypt during rotation: {}", e))?;
            
            entry.encrypted_data = new_encrypted_data;
            entry.nonce = new_nonce_bytes;
        }
        
        // Update master key
        self.master_key = new_master_key;
        
        // Save updated keystore
        self.save_keys()?;
        self.save_master_key()?;
        
        Ok(())
    }
    
    /// Clean up expired keys
    pub fn cleanup_expired_keys(&mut self) -> Result<usize> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let initial_count = self.keys.len();
        
        self.keys.retain(|_, entry| {
            if let Some(expiry) = entry.metadata.expiry {
                current_time < expiry
            } else {
                true
            }
        });
        
        let removed_count = initial_count - self.keys.len();
        
        if removed_count > 0 {
            self.save_keys()?;
        }
        
        Ok(removed_count)
    }
    
    fn load_or_generate_master_key(storage_path: &Path) -> Result<Secret<[u8; 32]>> {
        let master_key_path = storage_path.with_extension("master");
        
        if master_key_path.exists() {
            Self::load_master_key(&master_key_path)
        } else {
            let master_key = Secret::new(secure_rng::random::array::<32>()?);
            Self::save_master_key_to_path(&master_key, &master_key_path)?;
            Ok(master_key)
        }
    }
    
    fn load_master_key(path: &Path) -> Result<Secret<[u8; 32]>> {
        let encrypted_data = fs::read(path)
            .context("Failed to read master key file")?;
        
        // For now, we'll use a simple key derivation from user password
        // In a real implementation, this would use platform-specific secure storage
        let password = Self::get_user_password()?;
        let derived_key = Self::derive_key_from_password(&password)?;
        
        let cipher = ChaCha20Poly1305::new(&derived_key);
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];
        
        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt master key: {}", e))?;
        
        if decrypted.len() != 32 {
            return Err(anyhow::anyhow!("Invalid master key size"));
        }
        
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&decrypted);
        
        Ok(Secret::new(key_array))
    }
    
    fn save_master_key(&self) -> Result<()> {
        let master_key_path = self.storage_path.with_extension("master");
        Self::save_master_key_to_path(&self.master_key, &master_key_path)
    }
    
    fn save_master_key_to_path(master_key: &Secret<[u8; 32]>, path: &Path) -> Result<()> {
        let password = Self::get_user_password()?;
        let derived_key = Self::derive_key_from_password(&password)?;
        
        let cipher = ChaCha20Poly1305::new(&derived_key);
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted = cipher
            .encrypt(nonce, master_key.expose_secret().as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt master key: {}", e))?;
        
        let mut file_data = Vec::with_capacity(12 + encrypted.len());
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&encrypted);
        
        fs::write(path, file_data)
            .context("Failed to write master key file")?;
        
        Ok(())
    }
    
    fn get_user_password() -> Result<String> {
        // In a real implementation, this would prompt the user or use platform keyring
        // For now, we'll use a simple environment variable
        std::env::var("QUBEE_KEYSTORE_PASSWORD")
            .or_else(|_| Ok("default_password".to_string()))
    }
    
    fn derive_key_from_password(password: &str) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();
        hasher.update(password.as_bytes());
        hasher.update(b"qubee_keystore_salt");
        
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.as_bytes()[..32]);
        
        Ok(key)
    }
    
    fn load_keys(&mut self) -> Result<()> {
        if !self.storage_path.exists() {
            return Ok(());
        }
        
        let data = fs::read(&self.storage_path)
            .context("Failed to read keystore file")?;
        
        if data.is_empty() {
            return Ok(());
        }
        
        self.keys = bincode::deserialize(&data)
            .context("Failed to deserialize keystore")?;
        
        Ok(())
    }
    
    fn save_keys(&self) -> Result<()> {
        let data = bincode::serialize(&self.keys)
            .context("Failed to serialize keystore")?;
        
        fs::write(&self.storage_path, data)
            .context("Failed to write keystore file")?;
        
        Ok(())
    }
}

impl Drop for SecureKeyStore {
    fn drop(&mut self) {
        // Attempt to save keys on drop
        let _ = self.save_keys();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    fn create_test_keystore() -> (SecureKeyStore, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("test_keystore.db");
        let keystore = SecureKeyStore::new(keystore_path).expect("Failed to create keystore");
        (keystore, temp_dir)
    }
    
    #[test]
    fn test_store_and_retrieve_key() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        
        let key_data = b"test_key_data_12345678901234567890";
        let metadata = KeyMetadata {
            algorithm: "ChaCha20Poly1305".to_string(),
            key_size: 32,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };
        
        // Store key
        keystore
            .store_key("test_key", key_data, KeyType::EncryptionKey, metadata)
            .expect("Failed to store key");
        
        // Retrieve key
        let retrieved = keystore
            .retrieve_key("test_key")
            .expect("Failed to retrieve key")
            .expect("Key not found");
        
        assert_eq!(retrieved.expose_secret(), key_data);
    }
    
    #[test]
    fn test_key_not_found() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        
        let result = keystore.retrieve_key("nonexistent_key").expect("Should not error");
        assert!(result.is_none());
    }
    
    #[test]
    fn test_delete_key() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        
        let key_data = b"test_key_data";
        let metadata = KeyMetadata {
            algorithm: "Test".to_string(),
            key_size: 13,
            usage: vec![KeyUsage::Signing],
            expiry: None,
            tags: HashMap::new(),
        };
        
        keystore
            .store_key("test_key", key_data, KeyType::SigningKey, metadata)
            .expect("Failed to store key");
        
        assert!(keystore.has_key("test_key"));
        
        let deleted = keystore.delete_key("test_key").expect("Failed to delete key");
        assert!(deleted);
        assert!(!keystore.has_key("test_key"));
    }
    
    #[test]
    fn test_list_keys() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        
        let metadata = KeyMetadata {
            algorithm: "Test".to_string(),
            key_size: 32,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };
        
        keystore
            .store_key("key1", b"data1", KeyType::EncryptionKey, metadata.clone())
            .expect("Failed to store key1");
        
        keystore
            .store_key("key2", b"data2", KeyType::SigningKey, metadata)
            .expect("Failed to store key2");
        
        let keys = keystore.list_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }
    
    #[test]
    fn test_master_key_rotation() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        
        let key_data = b"test_key_data_for_rotation";
        let metadata = KeyMetadata {
            algorithm: "Test".to_string(),
            key_size: 26,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };
        
        // Store a key
        keystore
            .store_key("test_key", key_data, KeyType::EncryptionKey, metadata)
            .expect("Failed to store key");
        
        // Rotate master key
        keystore.rotate_master_key().expect("Failed to rotate master key");
        
        // Verify key can still be retrieved
        let retrieved = keystore
            .retrieve_key("test_key")
            .expect("Failed to retrieve key after rotation")
            .expect("Key not found after rotation");
        
        assert_eq!(retrieved.expose_secret(), key_data);
    }
}
