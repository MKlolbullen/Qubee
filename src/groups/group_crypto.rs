use anyhow::Result;
use secrecy::Secret;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::groups::group_manager::GroupId;
use crate::security::secure_rng;

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
}