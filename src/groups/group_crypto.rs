use anyhow::Result;
use secrecy::Secret;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::groups::group_manager::GroupId;
use crate::security::secure_rng;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use secrecy::ExposeSecret;
use anyhow::Context;

/// Symmetric key used for encrypting group messages. It stores the raw
/// 256‑bit secret along with the creation timestamp. In a complete
/// implementation the key material would be encrypted at rest and
/// rotated periodically. Here it is kept in memory for simplicity.
pub struct GroupKey {
    /// Raw 256‑bit key material. Wrapped in `Secret` to prevent
    /// accidental disclosure.
    pub key: Secret<[u8; 32]>,
    /// Unix timestamp when the key was created.
    pub created_at: u64,
}

/// Metadata describing a key rotation event. When a group key is
/// rotated, an instance of this struct is returned detailing the
/// transition from the old key to the new one.
pub struct GroupKeyRotation {
    /// Identifier of the group whose key was rotated.
    pub group_id: GroupId,
    /// Creation time of the previous key, if one existed.
    pub old_key_created_at: u64,
    /// Creation time of the new key.
    pub new_key_created_at: u64,
    /// Timestamp when the rotation occurred.
    pub rotated_at: u64,
}

/// Manages symmetric keys for group chats. Keys are stored in a simple
/// in‑memory map keyed by `GroupId`. In a production system keys
/// should be stored in secure hardware or an encrypted keystore and
/// derived via a ratchet mechanism. This module provides just enough
/// functionality to allow the rest of the group manager to compile.
pub struct GroupCrypto {
    keys: HashMap<GroupId, GroupKey>,
}

impl GroupCrypto {
    /// Create a new `GroupCrypto` instance with no keys loaded.
    pub fn new() -> Result<Self> {
        Ok(GroupCrypto {
            keys: HashMap::new(),
        })
    }

    /// Generate a new symmetric key for a group. If a key already
    /// exists for the group it will be overwritten. Returns `Ok(())`
    /// on success.
    pub fn create_group_key(&mut self, group_id: GroupId) -> Result<()> {
        let key_bytes = secure_rng::random::array::<32>()?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        let group_key = GroupKey {
            key: Secret::new(key_bytes),
            created_at,
        };
        self.keys.insert(group_id, group_key);
        Ok(())
    }

    /// Rotate the symmetric key for a group. The old key is replaced
    /// with a newly generated one. Returns a `GroupKeyRotation`
    /// describing the change.
    pub fn rotate_group_key(&mut self, group_id: GroupId) -> Result<GroupKeyRotation> {
        let old_created_at = self
            .keys
            .get(&group_id)
            .map(|k| k.created_at)
            .unwrap_or(0);
        let new_key_bytes = secure_rng::random::array::<32>()?;
        let new_created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        let group_key = GroupKey {
            key: Secret::new(new_key_bytes),
            created_at: new_created_at,
        };
        self.keys.insert(group_id, group_key);
        Ok(GroupKeyRotation {
            group_id,
            old_key_created_at: old_created_at,
            new_key_created_at: new_created_at,
            rotated_at: new_created_at,
        })
    }

    /// Retrieve the current key for a group, if any.
    pub fn get_group_key(&self, group_id: &GroupId) -> Option<&GroupKey> {
        self.keys.get(group_id)
    }

    /// Encrypt a plaintext message for the given group using the
    /// current group key. A fresh nonce is generated for each
    /// encryption and is prefixed to the returned ciphertext. The
    /// resulting vector has the format `[nonce | ciphertext]`.
    pub fn encrypt_message(&self, group_id: &GroupId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .get_group_key(group_id)
            .ok_or_else(|| anyhow::anyhow!("Group key not found"))?;
        // Derive a cipher from the 256‑bit group key
        let cipher = ChaCha20Poly1305::new(key.key.expose_secret().into());
        // Generate a random 96‑bit nonce
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .context("Group message encryption failed")?;
        // Prepend nonce to ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt a group message. Expects the input to have the nonce
    /// prepended as returned by `encrypt_message`. Returns the
    /// plaintext on success.
    pub fn decrypt_message(&self, group_id: &GroupId, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        let key = self
            .get_group_key(group_id)
            .ok_or_else(|| anyhow::anyhow!("Group key not found"))?;
        let cipher = ChaCha20Poly1305::new(key.key.expose_secret().into());
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .context("Group message decryption failed")?;
        Ok(plaintext)
    }
}
