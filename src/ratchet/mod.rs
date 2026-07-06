//! Forward-secret, deniable, post-quantum 1:1 messaging.
//!
//! This module is the new cryptographic core replacing the previous
//! "sign every message with the long-term identity key" design (which
//! gave neither forward secrecy nor deniability). It has two halves:
//!
//! * [`pqxdh`] — the **PQXDH** initial key agreement: an X3DH-style set
//!   of X25519 Diffie-Hellmans (deniable — either party could compute
//!   them) combined with an ML-KEM-768 encapsulation (post-quantum
//!   "harvest-now-decrypt-later" protection). Produces the 32-byte
//!   shared secret that seeds the ratchet.
//! * [`double_ratchet`] — the **Double Ratchet**: per-message forward
//!   secrecy, post-compromise security on each round-trip, and
//!   deniable authentication (Poly1305 tag under a key both parties
//!   know — no signatures).
//!
//! Staging: this stage lands the primitives + exhaustive tests as a
//! self-contained module. Wiring it into the session store, the wire
//! format, the JNI bridge, and the group sender-keys layer happens in
//! subsequent, separately-reviewed stages (see
//! `docs/double-ratchet-design.md`).

pub mod direct_message;
pub mod double_ratchet;
pub mod pqxdh;
pub mod prekey_store;
pub mod session;

pub use double_ratchet::{DoubleRatchet, MessageHeader, MAX_SKIP};
pub use pqxdh::{PqxdhInitiatorResult, PrekeyBundlePublic, PrekeyBundleSecret};
