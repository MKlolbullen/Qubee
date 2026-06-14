use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use blake3::Hasher;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use crate::security::secure_rng;

/// Secure key storage with encryption and integrity protection.
///
/// Drop behaviour: we use a manual `impl Drop` (further down) that
/// best-effort flushes the keystore to disk. The `master_key` field
/// is wrapped in `SecretBox<[u8; 32]>` which already zeroises on drop,
/// so we don't need `#[derive(ZeroizeOnDrop)]` — combining that
/// derive with the manual impl produced two `Drop` impls and an
/// E0119 conflict.
pub struct SecureKeyStore {
    storage_path: PathBuf,
    /// Data-encryption key: every stored key entry is sealed under
    /// this with ChaCha20-Poly1305. Held only in memory.
    master_key: SecretBox<[u8; 32]>,
    /// Passphrase-derived wrapping key used to seal `master_key` on
    /// disk (`.master` file). Kept so `rotate_master_key` can re-persist
    /// the rotated master key without re-threading the raw passphrase.
    wrap_key: SecretBox<[u8; 32]>,
    keys: HashMap<String, EncryptedKeyEntry>,
}

/// Alias maintained for backwards compatibility with existing code. Some
/// parts of the codebase refer to `SecureKeystore` instead of
/// `SecureKeyStore`. This type alias prevents compilation errors
/// without changing all call sites.
pub type SecureKeystore = SecureKeyStore;

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
    /// Create a new secure key store whose master key is wrapped under
    /// the caller-supplied `passphrase`.
    ///
    /// **At-rest security depends entirely on this passphrase.** On
    /// Android it must be a high-entropy secret fetched from the
    /// hardware-backed Keystore (see `SqlCipherKeyProvider`), *not* a
    /// hardcoded value. The previous implementation derived the
    /// wrapping key from a hardcoded `"default_password"`, which made
    /// the on-disk private keys recoverable by anyone with the
    /// `.master` file — that hole is closed by requiring the passphrase
    /// here.
    ///
    /// The passphrase is expected to already be full-entropy (≥ 256
    /// bits of randomness). We therefore use BLAKE3's KDF mode
    /// (`derive_key`) rather than a memory-hard password stretcher:
    /// stretching only helps for low-entropy human passwords, and adds
    /// nothing when the input is a random 256-bit key.
    pub fn new<P: AsRef<Path>>(storage_path: P, passphrase: &[u8]) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();

        // Create storage directory if it doesn't exist
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create storage directory")?;
        }

        // Generate or load master key, wrapped under `passphrase`.
        let master_key = Self::load_or_generate_master_key(&storage_path, passphrase)?;
        let wrap_key = SecretBox::new(Box::new(Self::derive_key_from_passphrase(passphrase)));

        let mut keystore = SecureKeyStore {
            storage_path: storage_path.clone(),
            master_key,
            wrap_key,
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
    pub fn retrieve_key(&mut self, key_id: &str) -> Result<Option<SecretBox<Vec<u8>>>> {
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
        
        Ok(Some(SecretBox::new(Box::new(decrypted_data))))
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
        let new_master_key = SecretBox::new(Box::new(secure_rng::random::array::<32>()?));
        
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
    
    fn load_or_generate_master_key(
        storage_path: &Path,
        passphrase: &[u8],
    ) -> Result<SecretBox<[u8; 32]>> {
        let master_key_path = storage_path.with_extension("master");

        if master_key_path.exists() {
            Self::load_master_key(&master_key_path, passphrase)
        } else {
            let master_key = SecretBox::new(Box::new(secure_rng::random::array::<32>()?));
            Self::save_master_key_to_path(&master_key, &master_key_path, passphrase)?;
            Ok(master_key)
        }
    }

    fn load_master_key(path: &Path, passphrase: &[u8]) -> Result<SecretBox<[u8; 32]>> {
        let encrypted_data = fs::read(path)
            .context("Failed to read master key file")?;
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("master key file too short"));
        }

        // Primary path: unwrap with the caller's (Keystore-derived)
        // passphrase.
        let derived = Self::derive_key_from_passphrase(passphrase);
        if let Ok(key) = Self::try_decrypt_master(&encrypted_data, &derived) {
            return Ok(key);
        }

        // Migration path: a `.master` written by a pre-this-change
        // build was wrapped under a key derived from the hardcoded
        // legacy passphrase (a *different* derivation construction).
        // Detect that, and if it unwraps, transparently re-wrap under
        // the real passphrase so the next launch uses the secure key.
        // Non-destructive — existing identity material is preserved.
        let legacy = Self::derive_key_legacy();
        if let Ok(key) = Self::try_decrypt_master(&encrypted_data, &legacy) {
            Self::save_master_key_to_path(&key, path, passphrase)
                .context("re-wrapping legacy master key under Keystore passphrase")?;
            return Ok(key);
        }

        Err(anyhow::anyhow!(
            "Failed to decrypt master key (wrong passphrase or corrupt file)"
        ))
    }

    /// Attempt to unwrap the master-key file with an already-derived
    /// 32-byte wrapping key. Returns `Err` on AEAD failure (wrong key
    /// / tampering) so callers can try a fallback.
    fn try_decrypt_master(
        encrypted_data: &[u8],
        derived_key: &[u8; 32],
    ) -> Result<SecretBox<[u8; 32]>> {
        let cipher = ChaCha20Poly1305::new_from_slice(derived_key).expect("32-byte key");
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
        Ok(SecretBox::new(Box::new(key_array)))
    }

    /// Re-persist the in-memory `master_key` to disk, sealed under the
    /// stored passphrase-derived `wrap_key`. Used after rotation.
    fn save_master_key(&self) -> Result<()> {
        let master_key_path = self.storage_path.with_extension("master");
        Self::seal_master_key_to_path(
            &self.master_key,
            &master_key_path,
            self.wrap_key.expose_secret(),
        )
    }

    fn save_master_key_to_path(
        master_key: &SecretBox<[u8; 32]>,
        path: &Path,
        passphrase: &[u8],
    ) -> Result<()> {
        let derived_key = Self::derive_key_from_passphrase(passphrase);
        Self::seal_master_key_to_path(master_key, path, &derived_key)
    }

    fn seal_master_key_to_path(
        master_key: &SecretBox<[u8; 32]>,
        path: &Path,
        wrap_key: &[u8; 32],
    ) -> Result<()> {
        let cipher = ChaCha20Poly1305::new_from_slice(wrap_key).expect("32-byte key");
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

    /// Derive the 32-byte master-key-wrapping key from the supplied
    /// passphrase using BLAKE3's KDF mode. The context string is a
    /// fixed domain separator; the passphrase is the keying material.
    ///
    /// No memory-hard stretching: the passphrase is expected to be a
    /// full-entropy 256-bit secret from the platform Keystore, so a
    /// single KDF derivation is sufficient. (Stretching exists to slow
    /// brute force of *guessable* passwords; a random 256-bit key is
    /// not guessable.)
    fn derive_key_from_passphrase(passphrase: &[u8]) -> [u8; 32] {
        blake3::derive_key("qubee secure_keystore master-wrap v1", passphrase)
    }

    /// Reproduce the *exact* pre-this-change derivation
    /// (`BLAKE3("default_password" || "qubee_keystore_salt")[..32]`) so
    /// the migration path in [`load_master_key`] can unwrap a legacy
    /// `.master` file. Used only for one-time migration; never for
    /// writing. Once a legacy file is re-wrapped under the real
    /// passphrase this code path is never hit again for that install.
    fn derive_key_legacy() -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"default_password");
        hasher.update(b"qubee_keystore_salt");
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.as_bytes()[..32]);
        key
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
        let keystore = SecureKeyStore::new(keystore_path, b"test-keystore-passphrase").expect("Failed to create keystore");
        (keystore, temp_dir)
    }
    
    #[test]
    fn wrong_passphrase_cannot_open_keystore() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("ks.db");

        // Create + store a key under passphrase A.
        {
            let mut ks = SecureKeyStore::new(&path, b"passphrase-A").unwrap();
            ks.store_key(
                "k",
                b"super secret key material 0123456789",
                KeyType::IdentityKey,
                KeyMetadata {
                    algorithm: "x".into(),
                    key_size: 36,
                    usage: vec![KeyUsage::Signing],
                    expiry: None,
                    tags: HashMap::new(),
                },
            )
            .unwrap();
        }

        // Opening with a different passphrase must fail — the on-disk
        // master key won't unwrap. This is the property that makes the
        // at-rest encryption real: without the Keystore-derived
        // passphrase the private keys are unrecoverable.
        let reopened = SecureKeyStore::new(&path, b"passphrase-B");
        assert!(
            reopened.is_err(),
            "keystore opened under the wrong passphrase — at-rest encryption is broken",
        );

        // Sanity: the correct passphrase still opens it.
        let ok = SecureKeyStore::new(&path, b"passphrase-A");
        assert!(ok.is_ok(), "correct passphrase must still open");
    }

    #[test]
    fn legacy_master_key_migrates_to_real_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("ks.db");
        let master_path = path.with_extension("master");

        // Forge a legacy `.master` file: a random master key wrapped
        // under the old hardcoded `default_password` derivation, exactly
        // as the pre-this-change build would have written it.
        let legacy_master = SecretBox::new(Box::new(secure_rng::random::array::<32>().unwrap()));
        let legacy_wrap = SecureKeyStore::derive_key_legacy();
        SecureKeyStore::seal_master_key_to_path(&legacy_master, &master_path, &legacy_wrap)
            .unwrap();

        // Also store a key entry sealed under that legacy master key so
        // we can prove the migration preserves real data.
        {
            let cipher = ChaCha20Poly1305::new(legacy_master.expose_secret().into());
            let nonce_bytes = secure_rng::random::array::<12>().unwrap();
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = cipher.encrypt(nonce, b"legacy identity key".as_ref()).unwrap();
            let mut keys = HashMap::new();
            keys.insert(
                "id".to_string(),
                EncryptedKeyEntry {
                    encrypted_data: ct,
                    nonce: nonce_bytes,
                    key_type: KeyType::IdentityKey,
                    created_at: 0,
                    last_accessed: 0,
                    metadata: KeyMetadata {
                        algorithm: "x".into(),
                        key_size: 19,
                        usage: vec![],
                        expiry: None,
                        tags: HashMap::new(),
                    },
                },
            );
            fs::write(&path, bincode::serialize(&keys).unwrap()).unwrap();
        }

        // Open under the REAL passphrase. The migration path detects the
        // legacy wrapping, re-wraps under the real passphrase, and the
        // stored key is still retrievable.
        let mut ks = SecureKeyStore::new(&path, b"real-keystore-passphrase").unwrap();
        let got = ks.retrieve_key("id").unwrap().expect("legacy key survived migration");
        assert_eq!(got.expose_secret().as_slice(), b"legacy identity key");

        // After migration the `.master` is re-wrapped: opening with the
        // legacy passphrase derivation must NO LONGER work, and the real
        // passphrase must.
        drop(ks);
        let legacy_reopen = {
            let data = fs::read(&master_path).unwrap();
            SecureKeyStore::try_decrypt_master(&data, &SecureKeyStore::derive_key_legacy())
        };
        assert!(
            legacy_reopen.is_err(),
            "after migration the master key must no longer unwrap under the legacy key",
        );
        assert!(SecureKeyStore::new(&path, b"real-keystore-passphrase").is_ok());
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
