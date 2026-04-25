//! Wire protocol for distributed invite acceptance.
//!
//! When a joiner scans a `qubee://invite/<token>` QR they record the
//! receipt locally (see `GroupManager::record_external_invite_acceptance`)
//! *and* publish a [`GroupHandshake::RequestJoin`] over the gossipsub
//! global topic. The minting peer's JNI dispatch loop validates the
//! request, calls `add_member`, and replies with a
//! [`GroupHandshake::JoinAccepted`] carrying a snapshot of the group
//! state. The joiner promotes the receipt into a real local group on
//! receipt of that snapshot.
//!
//! This module owns just the wire format + signing contract. The
//! integration glue lives in `jni_api.rs`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::groups::group_manager::GroupId;
use crate::groups::group_permissions::Role;
use crate::identity::identity_key::{
    HybridSignature, IdentityId, IdentityKey, IdentityKeyPair,
};

/// Magic prefix on every handshake frame so the gossipsub dispatch
/// loop can route handshake traffic to the Rust-side handler instead
/// of forwarding raw bytes up to Kotlin.
pub const HANDSHAKE_MAGIC: &[u8] = b"QUBEE_GHS\x01";

/// Freshness window for handshake messages. A signed `RequestJoin` /
/// `JoinAccepted` older than this is rejected so a captured frame
/// can't be replayed against a different peer minutes later.
pub const HANDSHAKE_MAX_AGE_SECS: u64 = 5 * 60;

/// Flat snapshot of a group member as it travels on the wire. Mirrors
/// the public-facing fields of `GroupMember` minus the moderation
/// state, which is per-device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMemberSummary {
    pub identity_id: IdentityId,
    pub identity_key: IdentityKey,
    pub display_name: String,
    pub role: Role,
    pub joined_at: u64,
}

/// Body of a `RequestJoin` payload that gets bundled into the wire
/// envelope and signed end-to-end. Pulling it out of the enum lets us
/// hash the canonical bytes deterministically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestJoinBody {
    pub group_id: GroupId,
    pub invitation_code: String,
    pub joiner_public_key: IdentityKey,
    pub joiner_display_name: String,
}

/// Body of a `JoinAccepted` payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinAcceptedBody {
    pub group_id: GroupId,
    pub invitation_code: String,
    pub group_name: String,
    pub members: Vec<GroupMemberSummary>,
    /// Identity of the joiner this `JoinAccepted` is addressed to.
    /// Lets the joiner ignore acceptances meant for someone else and
    /// stops a third party from "echoing" a stale acceptance.
    pub joiner_id: IdentityId,
}

/// Body of a `JoinRejected` payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinRejectedBody {
    pub group_id: GroupId,
    pub invitation_code: String,
    pub joiner_id: IdentityId,
    pub reason: String,
}

/// Top-level handshake frame.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GroupHandshake {
    RequestJoin {
        body: RequestJoinBody,
        signature: HybridSignature,
    },
    JoinAccepted {
        body: JoinAcceptedBody,
        signature: HybridSignature,
    },
    JoinRejected {
        body: JoinRejectedBody,
        signature: HybridSignature,
    },
}

impl GroupHandshake {
    /// Encode the handshake as a self-describing byte string ready for
    /// gossipsub publication. The magic prefix lets the dispatcher
    /// recognise handshake traffic without having to bincode-decode
    /// every inbound message.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(HANDSHAKE_MAGIC.len() + 256);
        out.extend_from_slice(HANDSHAKE_MAGIC);
        out.extend_from_slice(&bincode::serialize(self).context("handshake serialize")?);
        Ok(out)
    }

    /// Inverse of `to_wire`. Returns `None` for any frame that doesn't
    /// carry the handshake magic, so non-handshake gossip is silently
    /// passed back to the regular Kotlin dispatcher.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HANDSHAKE_MAGIC.len() {
            return None;
        }
        if &bytes[..HANDSHAKE_MAGIC.len()] != HANDSHAKE_MAGIC {
            return None;
        }
        bincode::deserialize(&bytes[HANDSHAKE_MAGIC.len()..]).ok()
    }
}

// ---------------------------------------------------------------------------
// Canonical signing payloads
// ---------------------------------------------------------------------------
//
// Each handshake variant signs a deterministic byte string built from
// (a) the variant body and (b) a domain-separation tag. We don't sign
// the bincode of the variant itself because bincode is not
// canonical (HashMap iteration order, struct field reordering, …).

const REQUEST_JOIN_TAG: &[u8] = b"qubee_handshake_request_join_v1";
const JOIN_ACCEPTED_TAG: &[u8] = b"qubee_handshake_join_accepted_v1";
const JOIN_REJECTED_TAG: &[u8] = b"qubee_handshake_join_rejected_v1";

pub fn canonical_request_join(body: &RequestJoinBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(REQUEST_JOIN_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.invitation_code.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&bincode::serialize(&body.joiner_public_key)?);
    out.push(0u8);
    out.extend_from_slice(body.joiner_display_name.as_bytes());
    Ok(out)
}

pub fn canonical_join_accepted(body: &JoinAcceptedBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(JOIN_ACCEPTED_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.invitation_code.as_bytes());
    out.push(0u8);
    out.extend_from_slice(body.group_name.as_bytes());
    out.push(0u8);
    out.extend_from_slice(body.joiner_id.as_ref());
    out.push(0u8);
    // Members go in last; serialise each one independently so length
    // prefixes can't be ambiguous if the list is empty.
    out.extend_from_slice(&(body.members.len() as u32).to_le_bytes());
    for m in &body.members {
        out.extend_from_slice(&bincode::serialize(m)?);
    }
    Ok(out)
}

pub fn canonical_join_rejected(body: &JoinRejectedBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(JOIN_REJECTED_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.invitation_code.as_bytes());
    out.push(0u8);
    out.extend_from_slice(body.joiner_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.reason.as_bytes());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Sign / verify helpers
// ---------------------------------------------------------------------------

/// Build a signed `RequestJoin` from the joiner's identity keypair.
pub fn sign_request_join(
    keypair: &IdentityKeyPair,
    body: RequestJoinBody,
) -> Result<GroupHandshake> {
    let payload = canonical_request_join(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::RequestJoin { body, signature })
}

/// Verify the joiner's signature on a `RequestJoin`. Returns the body
/// on success.
pub fn verify_request_join(
    body: &RequestJoinBody,
    signature: &HybridSignature,
) -> Result<bool> {
    let payload = canonical_request_join(body)?;
    body.joiner_public_key
        .verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Build a signed `JoinAccepted` from the inviter's identity keypair.
pub fn sign_join_accepted(
    keypair: &IdentityKeyPair,
    body: JoinAcceptedBody,
) -> Result<GroupHandshake> {
    let payload = canonical_join_accepted(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::JoinAccepted { body, signature })
}

/// Verify a `JoinAccepted` came from a key that the joiner has
/// reason to trust (the inviter's `IdentityKey`, looked up from the
/// joiner's stored receipt).
pub fn verify_join_accepted(
    body: &JoinAcceptedBody,
    signature: &HybridSignature,
    expected_inviter: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_join_accepted(body)?;
    expected_inviter.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

pub fn sign_join_rejected(
    keypair: &IdentityKeyPair,
    body: JoinRejectedBody,
) -> Result<GroupHandshake> {
    let payload = canonical_join_rejected(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::JoinRejected { body, signature })
}

pub fn verify_join_rejected(
    body: &JoinRejectedBody,
    signature: &HybridSignature,
    expected_inviter: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_join_rejected(body)?;
    expected_inviter.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_request_join() -> (IdentityKeyPair, RequestJoinBody) {
        let kp = IdentityKeyPair::generate().unwrap();
        let body = RequestJoinBody {
            group_id: GroupId::from_bytes([9u8; 32]),
            invitation_code: "abc".to_string(),
            joiner_public_key: kp.public_key(),
            joiner_display_name: "Bob".to_string(),
        };
        (kp, body)
    }

    #[test]
    fn request_join_round_trip() {
        let (kp, body) = fresh_request_join();
        let signed = sign_request_join(&kp, body.clone()).unwrap();
        let wire = signed.to_wire().unwrap();
        let decoded = GroupHandshake::from_wire(&wire).unwrap();
        match decoded {
            GroupHandshake::RequestJoin { body: b, signature } => {
                assert_eq!(b.invitation_code, body.invitation_code);
                assert!(verify_request_join(&b, &signature).unwrap());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn forged_request_join_is_rejected() {
        let (_, body) = fresh_request_join();
        // Sign with a different key — body still claims the original pubkey.
        let attacker = IdentityKeyPair::generate().unwrap();
        let signed = sign_request_join(&attacker, body.clone()).unwrap();
        if let GroupHandshake::RequestJoin { signature, .. } = signed {
            // Verify against the body's *stated* joiner key, not the attacker's.
            assert!(!verify_request_join(&body, &signature).unwrap());
        }
    }

    #[test]
    fn non_handshake_bytes_decode_to_none() {
        assert!(GroupHandshake::from_wire(b"random gossip").is_none());
        assert!(GroupHandshake::from_wire(b"").is_none());
        assert!(GroupHandshake::from_wire(b"QUBEE_BAD\x01extra").is_none());
    }
}
