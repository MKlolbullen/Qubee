use anyhow::Result;
use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::groups::group_manager::GroupId;
use crate::groups::sender_keys::SenderChain;
use crate::identity::identity_key::IdentityId;
use crate::security::secure_rng;

/// Symmetric key used for encrypting group messages. It stores the raw
/// 256‑bit secret along with the creation timestamp. In a complete
/// implementation the key material would be encrypted at rest and
/// rotated periodically. Here it is kept in memory for simplicity.
pub struct GroupKey {
    /// Raw 256‑bit key material. Wrapped in `Secret` to prevent
    /// accidental disclosure.
    pub key: SecretBox<[u8; 32]>,
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

/// Manages per-group symmetric state. Two layers:
///
/// * **Group key** — shared 256-bit secret negotiated during the
///   join handshake (KEM-wrapped) and rotated on member-add/remove.
///   Seeds the per-sender chains; never used directly to encrypt
///   group messages anymore.
/// * **Sender chains** — one [`SenderChain`] per `(group, sender,
///   generation)` triple. Each member maintains their own send
///   chain plus a tracked recv chain for every other active sender
///   in groups they're members of. Forward secrecy at the message
///   level; chains reset every time `group.version` bumps.
///
/// Chain state is held in memory; the `GroupManager` layer is
/// responsible for persisting it to the encrypted keystore on
/// every encrypt/decrypt so a process restart doesn't desync
/// counters from the peer's view. `GroupCrypto` exposes
/// `serialize_sender_chain` / `install_sender_chain` for that
/// purpose.
pub struct GroupCrypto {
    keys: HashMap<GroupId, GroupKey>,
    sender_chains: HashMap<(GroupId, IdentityId, u64), SenderChain>,
}

impl GroupCrypto {
    /// Create a new `GroupCrypto` instance with no keys loaded.
    pub fn new() -> Result<Self> {
        Ok(GroupCrypto {
            keys: HashMap::new(),
            sender_chains: HashMap::new(),
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
            key: SecretBox::new(Box::new(key_bytes)),
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
            key: SecretBox::new(Box::new(new_key_bytes)),
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

    /// Install a group key received over the network (e.g. via the
    /// invite handshake's KEM-wrapped key transport). Replaces any
    /// existing key for the group.
    pub fn set_group_key(&mut self, group_id: GroupId, key_bytes: [u8; 32]) {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.keys.insert(
            group_id,
            GroupKey {
                key: SecretBox::new(Box::new(key_bytes)),
                created_at,
            },
        );
    }

    /// Read a copy of the raw group-key bytes for transport to a new
    /// member. Callers should immediately KEM-wrap the result and not
    /// hold onto the plaintext.
    pub fn export_group_key(&self, group_id: &GroupId) -> Option<[u8; 32]> {
        self.keys
            .get(group_id)
            .map(|k| *k.key.expose_secret())
    }

    /// Retrieve the current key for a group, if any.
    pub fn get_group_key(&self, group_id: &GroupId) -> Option<&GroupKey> {
        self.keys.get(group_id)
    }

    /// Encrypt a plaintext message under the local member's
    /// per-`(group, sender, generation)` send chain. Lazy-initialises
    /// the chain on first use from the group key + sender id +
    /// generation via [`SenderChain::from_group_seed`]; subsequent
    /// calls advance the chain. Returns the wire format
    /// `[counter: u32 BE][nonce: 12B][AEAD ct + tag]`.
    pub fn encrypt_with_sender_chain(
        &mut self,
        group_id: &GroupId,
        sender_id: &IdentityId,
        generation: u64,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let chain = self.ensure_sender_chain(group_id, sender_id, generation)?;
        chain.encrypt(plaintext, aad)
    }

    /// Decrypt a frame produced by `encrypt_with_sender_chain`,
    /// against the recv side of the same `(group, sender,
    /// generation)` chain. Lazy-initialises the chain on first use
    /// (deterministic from the same inputs as the sender), then
    /// advances it.
    pub fn decrypt_with_sender_chain(
        &mut self,
        group_id: &GroupId,
        sender_id: &IdentityId,
        generation: u64,
        wire: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let chain = self.ensure_sender_chain(group_id, sender_id, generation)?;
        chain.decrypt(wire, aad)
    }

    /// Get-or-init a sender chain. The chain is derived
    /// deterministically from `(group_key, group_id, sender_id,
    /// generation)`, so both peers (the sender and any tracking
    /// receiver) land on identical state when they first touch a
    /// `(group, sender, generation)` triple they haven't seen yet.
    fn ensure_sender_chain(
        &mut self,
        group_id: &GroupId,
        sender_id: &IdentityId,
        generation: u64,
    ) -> Result<&mut SenderChain> {
        let key_triple = (*group_id, *sender_id, generation);
        if !self.sender_chains.contains_key(&key_triple) {
            let group_key_bytes = self
                .keys
                .get(group_id)
                .ok_or_else(|| anyhow::anyhow!(
                    "no group key for {group_id:?}; chain seed unavailable"
                ))?
                .key
                .expose_secret();
            let chain = SenderChain::from_group_seed(
                group_key_bytes,
                group_id,
                sender_id,
                generation,
            )?;
            self.sender_chains.insert(key_triple, chain);
        }
        Ok(self
            .sender_chains
            .get_mut(&key_triple)
            .expect("just inserted"))
    }

    /// Serialize a sender chain for keystore persistence. Returns
    /// `None` if no such chain exists yet (caller hasn't touched
    /// this triple via encrypt/decrypt). The `GroupManager` layer
    /// calls this after every chain advance to write the new state
    /// to the encrypted keystore.
    pub fn serialize_sender_chain(
        &self,
        group_id: &GroupId,
        sender_id: &IdentityId,
        generation: u64,
    ) -> Result<Option<Vec<u8>>> {
        match self.sender_chains.get(&(*group_id, *sender_id, generation)) {
            Some(chain) => Ok(Some(chain.persist()?)),
            None => Ok(None),
        }
    }

    /// Install a previously persisted sender chain — used by
    /// `GroupManager::load_groups_from_storage` to restore chain
    /// state across process restarts.
    pub fn install_sender_chain(
        &mut self,
        group_id: &GroupId,
        sender_id: &IdentityId,
        generation: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let chain = SenderChain::restore(bytes)?;
        self.sender_chains
            .insert((*group_id, *sender_id, generation), chain);
        Ok(())
    }

    /// Forget any sender chains for a group whose generation is
    /// older than `min_generation`. Called after a key rotation:
    /// once `group.version` advances, frames from the old
    /// generation are rejected by the generation gate in
    /// `decrypt_group_message` anyway, so the chains can't be
    /// useful and just sit holding key material.
    pub fn drop_stale_sender_chains(&mut self, group_id: &GroupId, min_generation: u64) {
        self.sender_chains
            .retain(|(gid, _sid, gen), _| !(gid == group_id && *gen < min_generation));
    }
}
