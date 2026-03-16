use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::security::secure_rng;

const MASTER_KEY_VERSION: u8 = 1;
const KEYSTORE_VERSION: u8 = 1;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;
const PASSWORD_SALT_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
const MASTER_KEY_AAD: &[u8] = b"qubee.master-key.v1";
const KEYSTORE_AAD: &[u8] = b"qubee.keystore.v1";

pub struct SecureKeyStore {
    storage_path: PathBuf,
    master_key: Zeroizing<[u8; 32]>,
    keys: HashMap<String, EncryptedKeyEntry>,
}

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

#[derive(Serialize, Deserialize)]
struct MasterKeyEnvelope {
    version: u8,
    salt: [u8; PASSWORD_SALT_LEN],
    nonce: [u8; AEAD_NONCE_LEN],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct KeyStoreEnvelope {
    version: u8,
    nonce: [u8; AEAD_NONCE_LEN],
    ciphertext: Vec<u8>,
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
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).context("Failed to create storage directory")?;
        }

        let master_key = Self::load_or_generate_master_key(&storage_path)?;
        let mut keystore = SecureKeyStore {
            storage_path,
            master_key,
            keys: HashMap::new(),
        };
        keystore.load_keys()?;
        Ok(keystore)
    }

    pub fn store_key(
        &mut self,
        key_id: &str,
        key_data: &[u8],
        key_type: KeyType,
        metadata: KeyMetadata,
    ) -> Result<()> {
        if key_id.is_empty() || key_id.len() > 256 {
            return Err(anyhow!("Invalid key ID"));
        }

        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.master_key));
        let encrypted_data = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: key_data,
                    aad: key_id.as_bytes(),
                },
            )
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

        let current_time = now_secs()?;
        self.keys.insert(
            key_id.to_string(),
            EncryptedKeyEntry {
                encrypted_data,
                nonce: nonce_bytes,
                key_type,
                created_at: current_time,
                last_accessed: current_time,
                metadata,
            },
        );
        self.save_keys()?;
        Ok(())
    }

    pub fn retrieve_key(&mut self, key_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let entry = match self.keys.get_mut(key_id) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        entry.last_accessed = now_secs()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.master_key));
        let nonce = Nonce::from_slice(&entry.nonce);
        let decrypted_data = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: entry.encrypted_data.as_ref(),
                    aad: key_id.as_bytes(),
                },
            )
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        Ok(Some(Zeroizing::new(decrypted_data)))
    }

    pub fn delete_key(&mut self, key_id: &str) -> Result<bool> {
        let removed = self.keys.remove(key_id).is_some();
        if removed {
            self.save_keys()?;
        }
        Ok(removed)
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    pub fn get_key_metadata(&self, key_id: &str) -> Option<&KeyMetadata> {
        self.keys.get(key_id).map(|entry| &entry.metadata)
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    pub fn rotate_master_key(&mut self) -> Result<()> {
        let new_master_key = Zeroizing::new(secure_rng::random::array::<32>()?);
        let old_master_key = *self.master_key;
        let old_cipher = ChaCha20Poly1305::new(Key::from_slice(&old_master_key));
        let new_cipher = ChaCha20Poly1305::new(Key::from_slice(&*new_master_key));

        for (key_id, entry) in self.keys.iter_mut() {
            let decrypted_data = old_cipher
                .decrypt(
                    Nonce::from_slice(&entry.nonce),
                    Payload {
                        msg: entry.encrypted_data.as_ref(),
                        aad: key_id.as_bytes(),
                    },
                )
                .map_err(|e| anyhow!("Failed to decrypt during rotation: {e}"))?;

            let new_nonce_bytes = secure_rng::random::array::<12>()?;
            let new_encrypted_data = new_cipher
                .encrypt(
                    Nonce::from_slice(&new_nonce_bytes),
                    Payload {
                        msg: decrypted_data.as_ref(),
                        aad: key_id.as_bytes(),
                    },
                )
                .map_err(|e| anyhow!("Failed to encrypt during rotation: {e}"))?;

            entry.encrypted_data = new_encrypted_data;
            entry.nonce = new_nonce_bytes;
        }

        self.master_key = new_master_key;
        self.save_keys()?;
        self.save_master_key()?;
        Ok(())
    }

    pub fn cleanup_expired_keys(&mut self) -> Result<usize> {
        let current_time = now_secs()?;
        let initial_count = self.keys.len();
        self.keys.retain(|_, entry| match entry.metadata.expiry {
            Some(expiry) => current_time < expiry,
            None => true,
        });

        let removed_count = initial_count.saturating_sub(self.keys.len());
        if removed_count > 0 {
            self.save_keys()?;
        }
        Ok(removed_count)
    }

    fn load_or_generate_master_key(storage_path: &Path) -> Result<Zeroizing<[u8; 32]>> {
        let master_key_path = storage_path.with_extension("master");
        if master_key_path.exists() {
            Self::load_master_key(&master_key_path)
        } else {
            let master_key = Zeroizing::new(secure_rng::random::array::<32>()?);
            Self::save_master_key_to_path(&master_key, &master_key_path)?;
            Ok(master_key)
        }
    }

    fn load_master_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
        let data = fs::read(path).context("Failed to read master key file")?;
        let envelope: MasterKeyEnvelope = bincode::deserialize(&data).context("Failed to decode master key envelope")?;
        if envelope.version != MASTER_KEY_VERSION {
            return Err(anyhow!("Unsupported master key envelope version"));
        }

        let mut password = Self::get_user_password()?;
        let mut derived_key = Self::derive_key_from_password(&password, &envelope.salt)?;
        password.zeroize();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
        let decrypted = cipher
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: envelope.ciphertext.as_ref(),
                    aad: MASTER_KEY_AAD,
                },
            )
            .map_err(|e| anyhow!("Failed to decrypt master key: {e}"))?;
        derived_key.zeroize();

        if decrypted.len() != 32 {
            return Err(anyhow!("Invalid master key size"));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&decrypted);
        Ok(Zeroizing::new(key_array))
    }

    fn save_master_key(&self) -> Result<()> {
        let master_key_path = self.storage_path.with_extension("master");
        Self::save_master_key_to_path(&self.master_key, &master_key_path)
    }

    fn save_master_key_to_path(master_key: &Zeroizing<[u8; 32]>, path: &Path) -> Result<()> {
        let mut password = Self::get_user_password()?;
        let salt = secure_rng::random::array::<PASSWORD_SALT_LEN>()?;
        let mut derived_key = Self::derive_key_from_password(&password, &salt)?;
        password.zeroize();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&derived_key));
        let nonce_bytes = secure_rng::random::array::<AEAD_NONCE_LEN>()?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: master_key.as_ref(),
                    aad: MASTER_KEY_AAD,
                },
            )
            .map_err(|e| anyhow!("Failed to encrypt master key: {e}"))?;
        derived_key.zeroize();

        let envelope = MasterKeyEnvelope {
            version: MASTER_KEY_VERSION,
            salt,
            nonce: nonce_bytes,
            ciphertext: encrypted,
        };
        let serialized = bincode::serialize(&envelope).context("Failed to encode master key envelope")?;
        fs::write(path, serialized).context("Failed to write master key file")?;
        Ok(())
    }

    fn get_user_password() -> Result<String> {
        let password = std::env::var("QUBEE_KEYSTORE_PASSWORD")
            .context("QUBEE_KEYSTORE_PASSWORD must be set to unlock the secure keystore")?;
        if password.trim().is_empty() {
            return Err(anyhow!("QUBEE_KEYSTORE_PASSWORD must not be empty"));
        }
        Ok(password)
    }

    fn derive_key_from_password(password: &str, salt: &[u8; PASSWORD_SALT_LEN]) -> Result<[u8; 32]> {
        let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(32))
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow::anyhow!("Argon2id derivation failed: {e}"))?;
        Ok(key)
    }

    fn load_keys(&mut self) -> Result<()> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let data = fs::read(&self.storage_path).context("Failed to read keystore file")?;
        if data.is_empty() {
            return Ok(());
        }

        let envelope: KeyStoreEnvelope = bincode::deserialize(&data).context("Failed to decode encrypted keystore")?;
        if envelope.version != KEYSTORE_VERSION {
            return Err(anyhow!("Unsupported keystore envelope version"));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.master_key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: envelope.ciphertext.as_ref(),
                    aad: KEYSTORE_AAD,
                },
            )
            .map_err(|e| anyhow!("Failed to decrypt keystore: {e}"))?;
        self.keys = bincode::deserialize(&plaintext).context("Failed to deserialize decrypted keystore")?;
        Ok(())
    }

    fn save_keys(&self) -> Result<()> {
        let plaintext = bincode::serialize(&self.keys).context("Failed to serialize keystore")?;
        let nonce = secure_rng::random::array::<AEAD_NONCE_LEN>()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*self.master_key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: KEYSTORE_AAD,
                },
            )
            .map_err(|e| anyhow!("Failed to encrypt keystore: {e}"))?;

        let envelope = KeyStoreEnvelope {
            version: KEYSTORE_VERSION,
            nonce,
            ciphertext,
        };
        let encoded = bincode::serialize(&envelope).context("Failed to encode encrypted keystore")?;
        fs::write(&self.storage_path, encoded).context("Failed to write keystore file")?;
        Ok(())
    }
}

impl Drop for SecureKeyStore {
    fn drop(&mut self) {
        let _ = self.save_keys();
    }
}

fn now_secs() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System time is before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_keystore() -> (SecureKeyStore, TempDir) {
        std::env::set_var("QUBEE_KEYSTORE_PASSWORD", "test-password-123");
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("test_keystore.db");
        let keystore = SecureKeyStore::new(keystore_path).expect("Failed to create keystore");
        (keystore, temp_dir)
    }

    #[test]
    fn store_and_retrieve_key_roundtrip() {
        let (mut keystore, _temp_dir) = create_test_keystore();
        let key_data = b"test_key_data_12345678901234567890";
        let metadata = KeyMetadata {
            algorithm: "ChaCha20Poly1305".to_string(),
            key_size: 32,
            usage: vec![KeyUsage::Encryption],
            expiry: None,
            tags: HashMap::new(),
        };

        keystore
            .store_key("test_key", key_data, KeyType::EncryptionKey, metadata)
            .expect("Failed to store key");

        let retrieved = keystore
            .retrieve_key("test_key")
            .expect("Failed to retrieve key")
            .expect("Key not found");

        assert_eq!(&retrieved[..], key_data.as_slice());
    }

    #[test]
    fn rejects_missing_password() {
        std::env::remove_var("QUBEE_KEYSTORE_PASSWORD");
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keystore_path = temp_dir.path().join("test_keystore.db");
        let result = SecureKeyStore::new(keystore_path);
        assert!(result.is_err());
    }

    #[test]
    fn master_key_file_has_randomized_salt_and_nonce() {
        std::env::set_var("QUBEE_KEYSTORE_PASSWORD", "test-password-123");
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let path_a = temp_dir.path().join("a.db");
        let path_b = temp_dir.path().join("b.db");

        let _ = SecureKeyStore::new(&path_a).expect("keystore A should create");
        let _ = SecureKeyStore::new(&path_b).expect("keystore B should create");

        let a = fs::read(path_a.with_extension("master")).expect("master key file A should exist");
        let b = fs::read(path_b.with_extension("master")).expect("master key file B should exist");

        assert_ne!(a, b);
    }
}
