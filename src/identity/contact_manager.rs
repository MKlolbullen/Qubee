use std::collections::HashMap;
use crate::storage::secure_keystore::{SecureKeystore, KeyType, KeyMetadata, KeyUsage};
use tokio::sync::Mutex;
use std::sync::Arc;
use bincode;
use hex;
use std::collections::HashMap as StdHashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use tokio::sync::RwLock;

use serde::{Serialize, Deserialize};

use crate::identity::identity_key::{IdentityId, IdentityKey};

/// Represents the verification status of a contact. Applications may
/// choose different trust models (e.g. TOFU, cross‑signature). For
/// now we distinguish between verified and unverified contacts only.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ContactVerificationStatus {
    /// The contact's identity has been verified via an out‑of‑band
    /// channel or cryptographic signature.
    Verified,
    /// The contact has not been verified and should be treated with
    /// caution. In a real system users could be prompted to verify
    /// keys before exchanging sensitive information.
    Unverified,
    /// The contact is blocked and should not be able to initiate
    /// communication.
    Blocked,
}

/// Stores metadata about a user contact. Each contact is keyed by
/// their `IdentityId`. The `IdentityKey` is the public key used for
/// authentication and encryption; it may be rotated by the contact
/// manager if the remote party updates their identity. The
/// `display_name` is user‑provided and optional.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Contact {
    pub identity_id: IdentityId,
    pub identity_key: IdentityKey,
    pub display_name: String,
    pub verification_status: ContactVerificationStatus,
    pub added_at: u64,
}

/// Manages a collection of contacts. Contacts are stored in an
/// asynchronous read/write lock allowing concurrent lookups from
/// multiple tasks while writes (adding or updating contacts) are
/// serialized. In a real application this manager would persist
/// contacts to disk via an encrypted database.
pub struct ContactManager {
    contacts: RwLock<HashMap<IdentityId, Contact>>,
    /// Optional secure keystore for persisting contacts. If None,
    /// contacts are kept only in memory. When provided, each
    /// contact is stored under a key named `contact_{identity_id}`
    /// where `identity_id` is hex‑encoded.
    keystore: Option<Arc<Mutex<SecureKeystore>>>,
}

impl ContactManager {
    /// Create a new contact manager with no contacts.
    pub fn new() -> Self {
        ContactManager {
            contacts: RwLock::new(HashMap::new()),
            keystore: None,
        }
    }

    /// Create a new contact manager backed by a secure keystore.
    /// Contacts added through this manager will be persisted to the
    /// keystore, and existing contacts can be loaded from storage via
    /// `load_from_storage`. Note that `SecureKeystore` operations are
    /// performed behind a `tokio::sync::Mutex` to allow concurrent
    /// asynchronous access.
    pub fn new_with_keystore(keystore: SecureKeystore) -> Self {
        ContactManager {
            contacts: RwLock::new(HashMap::new()),
            keystore: Some(Arc::new(Mutex::new(keystore))),
        }
    }

    /// Add or update a contact. If a contact with the same
    /// `identity_id` already exists it will be replaced. This
    /// operation acquires a write lock.
    pub async fn add_contact(&self, contact: Contact) -> anyhow::Result<()> {
        // Insert into in‑memory map
        {
            let mut map = self.contacts.write().await;
            map.insert(contact.identity_id, contact.clone());
        }
        // Persist to keystore if configured
        if let Some(ref ks_arc) = self.keystore {
            let serialized = bincode::serialize(&contact)?;
            let key_name = format!("contact_{}", hex::encode(contact.identity_id.as_ref()));
            let metadata = KeyMetadata {
                algorithm: "bincode".to_string(),
                key_size: serialized.len(),
                usage: vec![KeyUsage::Encryption],
                expiry: None,
                tags: StdHashMap::new(),
            };
            let mut ks = ks_arc.lock().await;
            ks.store_key(&key_name, &serialized, KeyType::IdentityKey, metadata)?;
        }
        Ok(())
    }

    /// Retrieve a contact by `identity_id`. Returns a clone of the
    /// stored contact to avoid holding the read lock while the caller
    /// inspects the data.
    pub async fn get_contact(&self, identity_id: &IdentityId) -> Option<Contact> {
        let map = self.contacts.read().await;
        map.get(identity_id).cloned()
    }

    /// Convenience method to retrieve a contact's public identity key.
    pub async fn get_identity_key(&self, identity_id: &IdentityId) -> Option<IdentityKey> {
        self.get_contact(identity_id).await.map(|c| c.identity_key)
    }

    /// Convenience method to retrieve a contact's display name. If
    /// the contact is unknown `None` is returned.
    pub async fn get_display_name(&self, identity_id: &IdentityId) -> Option<String> {
        self.get_contact(identity_id)
            .await
            .map(|c| c.display_name)
    }

    /// Load contacts from the secure keystore into the in‑memory map.
    /// This method iterates over all keys in the keystore beginning
    /// with `contact_`, deserializes the stored contact records and
    /// populates the manager's internal map. It returns the number of
    /// contacts loaded on success.
    pub async fn load_from_storage(&self) -> anyhow::Result<usize> {
        let mut count = 0;
        if let Some(ref ks_arc) = self.keystore {
            // Obtain list of keys without holding the keystore lock
            let key_list = {
                let ks = ks_arc.lock().await;
                ks.list_keys()
            };
            for key_name in key_list.into_iter().filter(|k| k.starts_with("contact_")) {
                // Acquire lock each time we need to retrieve a key
                if let Some(secret_data) = {
                    let mut ks = ks_arc.lock().await;
                    ks.retrieve_key(&key_name)?
                } {
                    let data = secret_data.expose_secret();
                    if let Ok(contact) = bincode::deserialize::<Contact>(data) {
                        // Update in‑memory map
                        let mut map = self.contacts.write().await;
                        map.insert(contact.identity_id, contact);
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }
}
