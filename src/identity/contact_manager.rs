use std::collections::HashMap;
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
}

impl ContactManager {
    /// Create a new contact manager with no contacts.
    pub fn new() -> Self {
        ContactManager {
            contacts: RwLock::new(HashMap::new()),
        }
    }

    /// Add or update a contact. If a contact with the same
    /// `identity_id` already exists it will be replaced. This
    /// operation acquires a write lock.
    pub async fn add_contact(&self, contact: Contact) {
        let mut map = self.contacts.write().await;
        map.insert(contact.identity_id, contact);
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
}