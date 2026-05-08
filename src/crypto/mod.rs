//! Reusable cryptographic primitives that aren't tied to a specific
//! protocol surface. The active group flow lives in
//! `crate::groups`; identity/device keys live in
//! `crate::identity`. This module is for the small,
//! self-contained pieces that get composed into either.

pub mod enhanced_ratchet;

pub use enhanced_ratchet::{EnhancedHybridRatchet, RatchetRole};
