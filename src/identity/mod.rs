pub mod identity_key;
pub mod contact_manager;

// Signal-protocol prototype. Lives behind the `legacy` feature
// because it derives serde over `DevicePublicKey` (which contains
// pqcrypto types that don't impl serde) and wraps non-Zeroize types
// in `Secret`. See docs/build-status.md for the migration list.
#[cfg(feature = "legacy")]
pub mod signal_protocol;

pub use identity_key::{IdentityKey, IdentityKeyPair, DeviceKey, HybridSignature};
pub use contact_manager::{ContactManager, Contact, ContactVerificationStatus};
#[cfg(feature = "legacy")]
pub use signal_protocol::{SignalProtocol, PreKeyBundle, SignedPreKey};
