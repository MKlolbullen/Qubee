//! crypto/identity.rs //! Handles identity keys, one-time signatures, deniability, and secure storage of ratchet state.

use std::fs; use std::path::PathBuf; use std::sync::{Arc, Mutex}; use std::time::{Duration, Instant}; use ring::aead::{Aad, LessSafeKey, UnboundKey, AES_256_GCM, NONCE_LEN, Nonce}; use ring::pbkdf2; use rand::{RngCore, rngs::OsRng}; use serde::{Serialize, Deserialize}; use std::num::NonZeroU32; use zeroize::Zeroize;

const SALT: &[u8] = b"qubee-state-salt"; const PBKDF2_ITERATIONS: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(100_000) }; const KEY_LEN: usize = 32; // 256-bit AES key const AUTOLOCK_DURATION: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Serialize, Deserialize)] pub struct Identity { pub name: String, pub public_key: Vec<u8>, pub private_key: Vec<u8>, }

#[derive(Serialize, Deserialize)] pub struct StoredState { pub ratchet_state: Vec<u8>, pub timestamp: u64, }

pub struct IdentityManager { pub state_path: PathBuf, pub key: LessSafeKey, last_access: Arc<Mutex<Instant>>, }

impl IdentityManager { pub fn new(password: &str, state_path: PathBuf) -> Self { let mut derived_key = [0u8; KEY_LEN]; pbkdf2::derive( pbkdf2::PBKDF2_HMAC_SHA256, PBKDF2_ITERATIONS, SALT, password.as_bytes(), &mut derived_key, );

let unbound = UnboundKey::new(&AES_256_GCM, &derived_key).unwrap();
    derived_key.zeroize();
    let key = LessSafeKey::new(unbound);

    IdentityManager {
        state_path,
        key,
        last_access: Arc::new(Mutex::new(Instant::now())),
    }
}

pub fn save_state(&self, state: &StoredState) -> Result<(), Box<dyn std::error::Error>> {
    let nonce_bytes = self.random_nonce();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut serialized = bincode::serialize(state)?;
    self.key.seal_in_place_append_tag(nonce, Aad::empty(), &mut serialized)?;

    let mut data = nonce_bytes.to_vec();
    data.extend_from_slice(&serialized);
    fs::write(&self.state_path, data)?;

    Ok(())
}

pub fn load_state(&self) -> Result<StoredState, Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut last = self.last_access.lock().unwrap();
    if now.duration_since(*last) > AUTOLOCK_DURATION {
        return Err("State is locked. Password re-authentication required.".into());
    }
    *last = now;

    let bytes = fs::read(&self.state_path)?;
    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)?;
    let mut decrypted = ciphertext.to_vec();
    let plaintext = self.key.open_in_place(nonce, Aad::empty(), &mut decrypted)?;
    let mut state: StoredState = bincode::deserialize(plaintext)?;
    state.ratchet_state.zeroize();
    Ok(state)
}

fn random_nonce(&self) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let suffix: u32 = OsRng.next_u32();
    nonce[..8].copy_from_slice(&now.to_le_bytes());
    nonce[8..].copy_from_slice(&suffix.to_le_bytes());
    nonce
}

}

pub struct SecureSession { pub identity: Identity, pub manager: IdentityManager, pub state: StoredState, }

impl SecureSession { pub fn unlock(password: &str, path: PathBuf, identity: Identity) -> Result<Self, Box<dyn std::error::Error>> { let manager = IdentityManager::new(password, path); let state = manager.load_state()?; Ok(SecureSession { identity, manager, state, }) }

pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
    self.manager.save_state(&self.state)
}

}
