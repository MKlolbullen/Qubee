//! Encrypted group-message envelope.
//!
//! Once a group has a shared symmetric key (negotiated via the join
//! handshake or rotated via [`crate::groups::handshake_handlers::plan_key_rotation`]),
//! members exchange messages over the per-group gossipsub topic as
//! [`GroupMessageEnvelope`] frames:
//!
//! ```text
//! MAGIC_GROUP_MESSAGE || bincode({
//!   body: GroupMessageBody { group_id, sender_id, generation,
//!                            aead_payload, timestamp },
//!   signature: HybridSignature(over canonical_group_message(body)),
//! })
//! ```
//!
//! Authenticity comes from two layers: the AEAD (gives you "someone
//! who knew the group key wrote this") plus the sender's hybrid
//! signature (gives you "this specific member wrote this", so members
//! can't impersonate each other inside the group).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::groups::group_manager::{GroupId, GroupManager};
use crate::identity::identity_key::{
    HybridSignature, IdentityId, IdentityKey, IdentityKeyPair,
};

/// Magic prefix for a group-message frame. Distinct from the
/// handshake magic so the dispatch loop can tell the two apart
/// without a bincode round-trip.
pub const MAGIC_GROUP_MESSAGE: &[u8] = b"QUBEE_GMS\x01";

/// Maximum age of a group message frame. Bounds the replay window
/// for a captured frame. 5 minutes matches the rest of the protocol.
pub const GROUP_MESSAGE_MAX_AGE_SECS: u64 = 5 * 60;

const GROUP_MESSAGE_TAG: &[u8] = b"qubee_group_message_v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMessageBody {
    pub group_id: GroupId,
    pub sender_id: IdentityId,
    /// Snapshot of the group's `version` counter at send time.
    /// Lets receivers detect "this was encrypted under an older key
    /// I no longer have", though for now we simply attempt decryption
    /// against the current key and fall through to logging.
    pub generation: u64,
    /// `[nonce(12) || ciphertext]` from
    /// [`GroupCrypto::encrypt_message`].
    pub aead_payload: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMessageEnvelope {
    pub body: GroupMessageBody,
    pub signature: HybridSignature,
}

impl GroupMessageEnvelope {
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(MAGIC_GROUP_MESSAGE.len() + 256);
        out.extend_from_slice(MAGIC_GROUP_MESSAGE);
        out.extend_from_slice(&bincode::serialize(self).context("group message serialize")?);
        Ok(out)
    }

    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MAGIC_GROUP_MESSAGE.len() {
            return None;
        }
        if &bytes[..MAGIC_GROUP_MESSAGE.len()] != MAGIC_GROUP_MESSAGE {
            return None;
        }
        bincode::deserialize(&bytes[MAGIC_GROUP_MESSAGE.len()..]).ok()
    }
}

/// Canonical bytes the sender's [`HybridSignature`] covers. Built by
/// hand (not bincode) so signatures stay stable across struct field
/// reordering or future serde tweaks.
pub fn canonical_group_message(body: &GroupMessageBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + body.aead_payload.len());
    out.extend_from_slice(GROUP_MESSAGE_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.sender_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.generation.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&(body.aead_payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.aead_payload);
    out
}

/// Decrypted plaintext + sender metadata. Returned to callers (and
/// surfaced to Kotlin) once the envelope is validated end-to-end.
#[derive(Clone, Debug)]
pub struct DecryptedGroupMessage {
    pub group_id: GroupId,
    pub sender_id: IdentityId,
    pub generation: u64,
    pub plaintext: Vec<u8>,
    pub timestamp: u64,
}

/// Encrypt a plaintext message for the named group, sign the envelope
/// with the sender's identity keypair, and return the wire-ready
/// bytes (with [`MAGIC_GROUP_MESSAGE`] prefix).
///
/// The group must already have a key installed in `gm`'s GroupCrypto;
/// callers can assume that's the case after a successful join or
/// `plan_key_rotation`.
pub fn encrypt_group_message(
    gm: &GroupManager,
    sender_identity: &IdentityKeyPair,
    group_id: GroupId,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let group = gm
        .get_group(&group_id)
        .ok_or_else(|| anyhow!("encrypt: unknown group"))?;
    let aead_payload = gm.encrypt_group_message(&group_id, plaintext)?;
    let body = GroupMessageBody {
        group_id,
        sender_id: sender_identity.identity_id(),
        generation: group.version,
        aead_payload,
        timestamp: now_secs(),
    };
    let payload = canonical_group_message(&body);
    let signature = sender_identity.sign(&payload).context("sign group message")?;
    let envelope = GroupMessageEnvelope { body, signature };
    envelope.to_wire()
}

/// Validate + decrypt a wire-format group-message frame.
///
/// Steps:
///   1. Reject unless the magic prefix is right.
///   2. Reject unless the sender is an *active* member of the group
///      (so a former member's captured key can't be replayed once
///      they're rotated out).
///   3. Verify the sender's signature against the canonical payload.
///   4. Decrypt the AEAD payload with the current group key.
///   5. Return the plaintext + sender id + timestamp.
///
/// Step 2 is the linchpin of "removed members can't keep talking" —
/// `process_key_rotation` flips the kicked member's status, so any
/// later GroupMessage from them is rejected here on purely local
/// state.
pub fn decrypt_group_message(
    gm: &GroupManager,
    wire: &[u8],
) -> Result<DecryptedGroupMessage> {
    let envelope = GroupMessageEnvelope::from_wire(wire)
        .ok_or_else(|| anyhow!("not a group message frame"))?;
    let body = &envelope.body;

    let group = gm
        .get_group(&body.group_id)
        .ok_or_else(|| anyhow!("decrypt: unknown group"))?;

    // Generation gate: closes the small race where a kicked-then-
    // rotated member's already-in-flight message lands after the
    // local rotation but before the gossipsub mesh has fully
    // settled. `body.generation` is the sender's snapshot of
    // `group.version` at send time; we accept only equal-version
    // frames. Strict policy because the alternative — buffer
    // future-generation frames until the matching KeyRotation
    // arrives — needs reorder-safe state we don't yet have.
    if body.generation != group.version {
        return Err(anyhow!(
            "decrypt: generation mismatch (frame={}, local={})",
            body.generation,
            group.version
        ));
    }

    let sender = group
        .members
        .get(&body.sender_id)
        .ok_or_else(|| anyhow!("decrypt: sender not in group"))?;
    if !matches!(sender.member_status, crate::groups::group_manager::MemberStatus::Active) {
        return Err(anyhow!("decrypt: sender is not an active member"));
    }
    let sender_key: IdentityKey = sender.identity_key.clone();

    let payload = canonical_group_message(body);
    if !sender_key.verify_with_max_age(&payload, &envelope.signature, GROUP_MESSAGE_MAX_AGE_SECS)? {
        return Err(anyhow!("decrypt: signature failed or message expired"));
    }

    let plaintext = gm
        .decrypt_group_message(&body.group_id, &body.aead_payload)
        .context("AEAD decrypt")?;

    Ok(DecryptedGroupMessage {
        group_id: body.group_id,
        sender_id: body.sender_id,
        generation: body.generation,
        plaintext,
        timestamp: body.timestamp,
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
