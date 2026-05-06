pub mod contact_manager;
pub mod identity_key;

// Signal-protocol prototype. Lives behind the `legacy` feature
// because it derives serde over `DevicePublicKey` (which contains
// pqcrypto types that don't impl serde) and wraps non-Zeroize types
// in `Secret`. See docs/build-status.md for the migration list.
#[cfg(feature = "legacy")]
pub mod signal_protocol;

pub use contact_manager::{Contact, ContactManager, ContactVerificationStatus};
pub use identity_key::{DeviceKey, HybridSignature, IdentityKey, IdentityKeyPair};
#[cfg(feature = "legacy")]
pub use signal_protocol::{PreKeyBundle, SignalProtocol, SignedPreKey};
