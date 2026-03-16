use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Key, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const AUTOLOCK_DURATION: Duration = Duration::from_secs(300);
const PASSWORD_SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const STATE_AAD: &[u8] = b"qubee.state.v2";

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct StoredState {
    pub ratchet_state: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct StoredStateEnvelope {
    version: u8,
    salt: [u8; PASSWORD_SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

pub struct IdentityManager {
    pub state_path: PathBuf,
    password: String,
    last_access: Arc<Mutex<Instant>>,
}

impl IdentityManager {
    pub fn new(password: &str, state_path: PathBuf) -> Self {
        IdentityManager {
            state_path,
            password: password.to_string(),
            last_access: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub fn save_state(&self, state: &StoredState) -> Result<(), Box<dyn std::error::Error>> {
        let salt = random_salt();
        let mut key = derive_key(&self.password, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        let nonce = random_nonce();
        let mut serialized = bincode::serialize(state)?;
        let ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: serialized.as_ref(),
                aad: STATE_AAD,
            },
        )?;
        serialized.zeroize();
        key.zeroize();

        let envelope = StoredStateEnvelope {
            version: 2,
            salt,
            nonce,
            ciphertext,
        };

        let data = bincode::serialize(&envelope)?;
        fs::write(&self.state_path, data)?;
        Ok(())
    }

    pub fn load_state(&self) -> Result<StoredState, Box<dyn std::error::Error>> {
        let now = Instant::now();
        let mut last = self.last_access.lock().map_err(|_| "state lock poisoned")?;
        if now.duration_since(*last) > AUTOLOCK_DURATION {
            return Err("State is locked. Password re-authentication required.".into());
        }
        *last = now;

        let bytes = fs::read(&self.state_path)?;
        let envelope: StoredStateEnvelope = bincode::deserialize(&bytes)?;
        if envelope.version != 2 {
            return Err("Unsupported encrypted state version".into());
        }

        let mut key = derive_key(&self.password, &envelope.salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut decrypted = cipher.decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: envelope.ciphertext.as_ref(),
                aad: STATE_AAD,
            },
        )?;
        key.zeroize();

        let state: StoredState = bincode::deserialize(&decrypted)?;
        decrypted.zeroize();
        Ok(state)
    }
}

impl Drop for IdentityManager {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

pub struct SecureSession {
    pub identity: Identity,
    pub manager: IdentityManager,
    pub state: StoredState,
}

impl SecureSession {
    pub fn unlock(password: &str, path: PathBuf, identity: Identity) -> Result<Self, Box<dyn std::error::Error>> {
        let manager = IdentityManager::new(password, path);
        let state = manager.load_state()?;
        Ok(SecureSession { identity, manager, state })
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.manager.save_state(&self.state)
    }
}

fn derive_key(password: &str, salt: &[u8; PASSWORD_SALT_LEN]) -> Result<[u8; KEY_LEN], Box<dyn std::error::Error>> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    Ok(key)
}

fn random_salt() -> [u8; PASSWORD_SALT_LEN] {
    let mut salt = [0u8; PASSWORD_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrips_state_without_zeroizing_return_value() {
        let dir = TempDir::new().expect("temp dir should create");
        let manager = IdentityManager::new("correct horse battery staple", dir.path().join("state.bin"));
        let state = StoredState {
            ratchet_state: vec![1, 2, 3, 4, 5],
            timestamp: 123,
        };

        manager.save_state(&state).expect("state should save");
        let loaded = manager.load_state().expect("state should load");

        assert_eq!(loaded.ratchet_state, vec![1, 2, 3, 4, 5]);
        assert_eq!(loaded.timestamp, 123);
    }

    #[test]
    fn encrypted_state_file_changes_between_saves() {
        let dir = TempDir::new().expect("temp dir should create");
        let path = dir.path().join("state.bin");
        let manager = IdentityManager::new("correct horse battery staple", path.clone());
        let state = StoredState {
            ratchet_state: vec![9, 8, 7],
            timestamp: 456,
        };

        manager.save_state(&state).expect("first save should work");
        let first = fs::read(&path).expect("first ciphertext should exist");
        manager.save_state(&state).expect("second save should work");
        let second = fs::read(&path).expect("second ciphertext should exist");

        assert_ne!(first, second);
    }
}
