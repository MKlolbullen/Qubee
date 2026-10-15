use super::secure_keystore::KeyUsage;

/// Refusals the keystore makes before it touches key material. They
/// travel inside `anyhow::Error`; `downcast_ref::<KeystoreError>()`
/// tells an expired key from an absent one where that matters.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeystoreError {
    /// `expiry` is an exclusive upper bound: at exactly that second the
    /// key is already unusable.
    #[error("key '{key_id}' expired at {expiry}")]
    Expired { key_id: String, expiry: u64 },
    #[error("key '{key_id}' was not stored for {purpose:?}")]
    UsageDenied { key_id: String, purpose: KeyUsage },
}
