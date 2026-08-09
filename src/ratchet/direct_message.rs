//! Direct (1:1) message wire frame (Ratchet Stage 3c).
//!
//! The on-wire envelope for a forward-secret 1:1 message. It carries the
//! Double Ratchet header (in the clear — it's bound as AEAD associated
//! data by the ratchet, so tampering fails decryption) plus the
//! ciphertext, and — on the *first* message of a conversation — the PQXDH
//! [`InitialMessage`] the responder needs to complete the handshake.
//!
//! Unlike the group-message envelope this frame is **not** signed: 1:1
//! authenticity + integrity come from the ratchet's Poly1305 tag under a
//! key both parties derive, which is exactly what makes the transcript
//! deniable. The magic prefix lets the dispatcher route direct traffic
//! without decoding every inbound gossip frame.
//!
//! This stage defines + pins the frame. Consuming it on the live
//! send/receive path (looking up / establishing the [`super::session::Session`]
//! and threading it through JNI) is Stage 3d.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::groups::group_handshake::bounded_bincode_deserialize;
use crate::identity::identity_key::IdentityId;
use crate::ratchet::double_ratchet::MessageHeader;
use crate::ratchet::pqxdh::WireInitialMessage;

/// Magic prefix for the current direct-message frame. `\x02` adds an
/// opaque per-message routing envelope so route-less bootstrap traffic does
/// not expose either Qubee IdentityId outside the ratchet ciphertext.
pub const MAGIC_DIRECT_MESSAGE: &[u8] = b"QUBEE_DMS\x02";

const DIRECT_ID_SELECTOR_TAG: &[u8] = b"qubee_direct_identity_selector_v1";
pub const DIRECT_ROUTE_NONCE_LEN: usize = 16;
pub const DIRECT_ID_SELECTOR_LEN: usize = 16;

/// Domain-separated, per-message opaque handle for one Qubee identity.
/// IdentityIds are 256-bit public-key-derived values; the fresh route nonce
/// prevents a stable wire handle while making inversion infeasible to a party
/// that does not already know the identity. Parties that *do* know an identity
/// can test it — the same knowledge already lets them derive its blinded inbox.
pub fn direct_identity_selector(
    identity: &IdentityId,
    route_nonce: &[u8; DIRECT_ROUTE_NONCE_LEN],
) -> [u8; DIRECT_ID_SELECTOR_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(DIRECT_ID_SELECTOR_TAG);
    h.update(route_nonce);
    h.update(identity.as_ref());
    let mut out = [0u8; DIRECT_ID_SELECTOR_LEN];
    out.copy_from_slice(&h.finalize().as_bytes()[..DIRECT_ID_SELECTOR_LEN]);
    out
}

/// A single 1:1 ratchet message on the wire.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct DirectMessage {
    /// Fresh random nonce for this frame's endpoint selectors.
    pub route_nonce: [u8; DIRECT_ROUTE_NONCE_LEN],
    /// Opaque selector for the sender. The receiver resolves it only against
    /// identities with signature-verified prekey bundles in the Rust keystore.
    pub sender_selector: [u8; DIRECT_ID_SELECTOR_LEN],
    /// Opaque selector for the intended recipient. The local device verifies
    /// this against its own identity before touching ratchet state; the sender
    /// resolves the same selector on crash/retry to recover the destination.
    pub recipient_selector: [u8; DIRECT_ID_SELECTOR_LEN],
    /// Present only on the conversation's first message: the PQXDH
    /// initial handshake material. `None` on every subsequent message.
    pub initial: Option<WireInitialMessage>,
    /// The Double Ratchet header (sender DH public, previous-chain
    /// length, message index). Sent in the clear but bound as AEAD
    /// associated data, so tampering fails decryption.
    pub header: MessageHeader,
    /// The ratchet ciphertext (ChaCha20-Poly1305 output).
    pub ciphertext: Vec<u8>,
}

impl DirectMessage {
    /// Encode as a magic-prefixed byte string for transport/storage.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(MAGIC_DIRECT_MESSAGE.len() + 128 + self.ciphertext.len());
        out.extend_from_slice(MAGIC_DIRECT_MESSAGE);
        out.extend_from_slice(&bincode::serialize(self).context("direct message serialize")?);
        Ok(out)
    }

    /// Inverse of [`to_wire`]. Returns `None` for any frame lacking the
    /// direct-message magic, so non-direct gossip flows on to the regular
    /// dispatcher. The bincode decode is size-bounded because it runs on
    /// unauthenticated bytes *before* the ratchet AEAD check.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MAGIC_DIRECT_MESSAGE.len() {
            return None;
        }
        if &bytes[..MAGIC_DIRECT_MESSAGE.len()] != MAGIC_DIRECT_MESSAGE {
            return None;
        }
        bounded_bincode_deserialize(&bytes[MAGIC_DIRECT_MESSAGE.len()..]).ok()
    }
}

/// True if `bytes` carries the direct-message magic — a cheap prefix
/// check for the inbound dispatcher, mirroring `is_group_message_frame`.
pub fn is_direct_message_frame(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC_DIRECT_MESSAGE.len()
        && &bytes[..MAGIC_DIRECT_MESSAGE.len()] == MAGIC_DIRECT_MESSAGE
}

/// Read only the opaque routing tuple from a syntactically valid frame.
/// Identity resolution is intentionally stateful and lives in `direct.rs`,
/// where candidates come from the signature-verified prekey cache.
pub fn inspect_direct_selectors(
    bytes: &[u8],
) -> Option<(
    [u8; DIRECT_ROUTE_NONCE_LEN],
    [u8; DIRECT_ID_SELECTOR_LEN],
    [u8; DIRECT_ID_SELECTOR_LEN],
)> {
    DirectMessage::from_wire(bytes)
        .map(|dm| (dm.route_nonce, dm.sender_selector, dm.recipient_selector))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::pqxdh::{generate_bundle, initiate};
    use x25519_dalek::StaticSecret;

    fn sample_initial() -> WireInitialMessage {
        let (bob_secret, kem_pub) = generate_bundle().unwrap();
        let bob_public = bob_secret.public_with_kem(kem_pub);
        let alice_identity = StaticSecret::from([7u8; 32]);
        let init = initiate(&alice_identity, &bob_public).unwrap();
        WireInitialMessage::from_message(&init.initial_message)
    }

    #[test]
    fn magic_is_pinned() {
        assert_eq!(MAGIC_DIRECT_MESSAGE, b"QUBEE_DMS\x02");
    }

    #[test]
    fn round_trips_first_message_with_initial() {
        let sender = IdentityId::from([4u8; 32]);
        let recipient = IdentityId::from([6u8; 32]);
        let route_nonce = [0x41u8; DIRECT_ROUTE_NONCE_LEN];
        let dm = DirectMessage {
            route_nonce,
            sender_selector: direct_identity_selector(&sender, &route_nonce),
            recipient_selector: direct_identity_selector(&recipient, &route_nonce),
            initial: Some(sample_initial()),
            header: MessageHeader {
                dh: [9u8; 32],
                pn: 3,
                n: 7,
            },
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let wire = dm.to_wire().unwrap();
        assert!(is_direct_message_frame(&wire));
        assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
    }

    #[test]
    fn round_trips_subsequent_message_without_initial() {
        let sender = IdentityId::from([5u8; 32]);
        let recipient = IdentityId::from([7u8; 32]);
        let route_nonce = [0x52u8; DIRECT_ROUTE_NONCE_LEN];
        let dm = DirectMessage {
            route_nonce,
            sender_selector: direct_identity_selector(&sender, &route_nonce),
            recipient_selector: direct_identity_selector(&recipient, &route_nonce),
            initial: None,
            header: MessageHeader {
                dh: [0u8; 32],
                pn: 0,
                n: 12,
            },
            ciphertext: vec![0xAB; 64],
        };
        let wire = dm.to_wire().unwrap();
        assert_eq!(DirectMessage::from_wire(&wire).unwrap(), dm);
        assert_eq!(
            inspect_direct_selectors(&wire),
            Some((route_nonce, dm.sender_selector, dm.recipient_selector))
        );
        assert!(!wire.windows(32).any(|w| w == sender.as_ref()));
        assert!(!wire.windows(32).any(|w| w == recipient.as_ref()));
        let other_nonce = [0x53u8; DIRECT_ROUTE_NONCE_LEN];
        assert_ne!(
            direct_identity_selector(&recipient, &route_nonce),
            direct_identity_selector(&recipient, &other_nonce),
            "selector must rotate with the per-message nonce",
        );
    }

    #[test]
    fn rejects_foreign_and_truncated_frames() {
        // A group frame (wrong magic) is not a direct message.
        assert!(DirectMessage::from_wire(b"QUBEE_GMS\x02payload").is_none());
        assert!(!is_direct_message_frame(b"QUBEE_GMS\x02"));
        // Too-short input never panics.
        assert!(DirectMessage::from_wire(b"QU").is_none());
        assert!(DirectMessage::from_wire(&[]).is_none());
    }
}
