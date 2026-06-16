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
use crate::identity::identity_key::{HybridSignature, IdentityId, IdentityKey, IdentityKeyPair};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use crate::security::secure_rng;

/// Magic prefix for a group-message frame.
///
/// `\x02` is the sealed-outer-envelope wire format: the only plaintext
/// metadata on the wire is the group id (which is already revealed by
/// the gossipsub topic name) and the outer AEAD nonce. Everything else
/// — sender id, generation, timestamp, hybrid signature, the inner
/// AEAD ciphertext — is encrypted under a key derived from the group
/// key, so a passive observer subscribed to the topic learns nothing
/// beyond "a member sent N bytes at some time".
///
/// `\x01` was the pre-sealing format that left the signed body
/// bincoded in plaintext. We don't accept `\x01` on the receive path
/// any more — pre-this-change builds have to upgrade. The pre-alpha
/// posture in `SECURITY.md` already documents that minor-version
/// upgrades may break in-flight messages.
pub const MAGIC_GROUP_MESSAGE: &[u8] = b"QUBEE_GMS\x02";

/// Domain-separation tag for the BLAKE3 KDF that turns the group key
/// into the outer-envelope ChaCha20-Poly1305 key. Distinct from any
/// other derivation in the protocol so a compromise of either layer's
/// key reveals nothing about the other.
const OUTER_ENVELOPE_KDF_CONTEXT: &str = "qubee outer envelope v1";

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
    /// Bincode the signed envelope. The resulting bytes are NEVER
    /// published as a standalone wire frame — real on-the-wire frames
    /// are always wrapped by [`seal_outer_envelope`] so the metadata
    /// stays encrypted. Exposed `pub` so the wire-stability proptest
    /// can round-trip an envelope structure independently of the
    /// outer-AEAD layer.
    pub fn to_inner_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("group message serialize")
    }

    pub fn from_inner_bincode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).context("group message deserialize")
    }
}

/// Returns `true` if `wire` carries the sealed-group-message magic
/// prefix. Cheap O(1) check used by the inbound dispatcher to route
/// frames without attempting a full AEAD decrypt.
pub fn is_group_message_frame(wire: &[u8]) -> bool {
    wire.len() >= MAGIC_GROUP_MESSAGE.len()
        && &wire[..MAGIC_GROUP_MESSAGE.len()] == MAGIC_GROUP_MESSAGE
}

/// Group-key → outer-AEAD-key KDF. BLAKE3 `derive_key` with a fixed
/// context string; the group key is the input keying material. The
/// derivation is domain-separated from any other use of the group key
/// (the inner AEAD uses the group key directly) so a vulnerability in
/// one layer doesn't bleed into the other.
fn derive_outer_envelope_key(group_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(OUTER_ENVELOPE_KDF_CONTEXT, group_key)
}

/// Wrap a bincoded signed envelope in the outer AEAD layer and return
/// the wire-ready bytes ready for gossipsub publication. Only the
/// `group_id` and the AEAD nonce are plaintext; everything else
/// (sender id, generation, timestamp, signature, inner ciphertext) is
/// sealed.
pub fn seal_outer_envelope(
    group_id: &GroupId,
    group_key: &[u8; 32],
    inner_bincoded: &[u8],
) -> Result<Vec<u8>> {
    let outer_key = derive_outer_envelope_key(group_key);
    let cipher = ChaCha20Poly1305::new_from_slice(&outer_key)
        .map_err(|_| anyhow!("invalid outer key length"))?;
    let nonce_bytes = secure_rng::random::array::<12>()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    // Bind the outer AEAD to the group_id by including it as
    // associated data — prevents a captured ciphertext from being
    // replayed onto a different group's topic.
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: inner_bincoded,
                aad: group_id.as_ref(),
            },
        )
        .map_err(|e| anyhow!("outer envelope seal: {e:?}"))?;

    let mut out = Vec::with_capacity(MAGIC_GROUP_MESSAGE.len() + 32 + 12 + ciphertext.len());
    out.extend_from_slice(MAGIC_GROUP_MESSAGE);
    out.extend_from_slice(group_id.as_ref());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Strip the outer-envelope layer. Returns `(group_id, inner_bincoded)`
/// on success.
///
/// `group_key_lookup` is a closure that takes the parsed `group_id`
/// and returns the current 32-byte group key for it, or `None` if the
/// receiver isn't a member. Two-stage because the wire carries
/// `group_id` in the clear (it's identical to the gossipsub topic
/// name), but the inner ciphertext can only be opened with the right
/// group key — so the parser first reads `group_id`, asks the caller
/// which key to use, then attempts AEAD.
pub fn open_outer_envelope(
    wire: &[u8],
    group_key_lookup: impl FnOnce(&GroupId) -> Option<[u8; 32]>,
) -> Result<(GroupId, Vec<u8>)> {
    if wire.len() < MAGIC_GROUP_MESSAGE.len() + 32 + 12 {
        return Err(anyhow!("outer envelope too short"));
    }
    if &wire[..MAGIC_GROUP_MESSAGE.len()] != MAGIC_GROUP_MESSAGE {
        return Err(anyhow!("not a sealed group-message frame"));
    }
    let mut offset = MAGIC_GROUP_MESSAGE.len();

    let mut group_id_bytes = [0u8; 32];
    group_id_bytes.copy_from_slice(&wire[offset..offset + 32]);
    let group_id = GroupId::from_bytes(group_id_bytes);
    offset += 32;

    let nonce = Nonce::from_slice(&wire[offset..offset + 12]);
    offset += 12;
    let ciphertext = &wire[offset..];

    let group_key = group_key_lookup(&group_id)
        .ok_or_else(|| anyhow!("outer envelope: unknown group / not a member"))?;
    let outer_key = derive_outer_envelope_key(&group_key);
    let cipher = ChaCha20Poly1305::new_from_slice(&outer_key)
        .map_err(|_| anyhow!("invalid outer key length"))?;
    let inner = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: group_id.as_ref(),
            },
        )
        .map_err(|e| anyhow!("outer envelope open: {e:?}"))?;
    Ok((group_id, inner))
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

/// Stable 16-byte identifier for a group message, derived
/// deterministically from the canonical body bytes via BLAKE3.
/// Both the sender (at encrypt time) and every receiver (at
/// decrypt time) compute the same id without coordination, so
/// delivery acks can reference messages without an explicit id
/// field on the wire envelope.
///
/// 16 bytes is enough for collision resistance under the threat
/// model (a sender can't usefully forge a collision against their
/// own outbound; the AEAD nonce in the body already guarantees
/// uniqueness under a fixed group key).
pub fn group_message_id(body: &GroupMessageBody) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"qubee_group_message_id_v1");
    hasher.update(&[0u8]);
    hasher.update(&canonical_group_message(body));
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

/// Convenience: parse a sealed wire envelope and extract its message
/// id. Used by the JNI side so the Kotlin caller of
/// `nativeSendGroupMessage` can persist the id for the row it just
/// wrote, without re-implementing the BLAKE3 in Kotlin.
///
/// Takes `&GroupManager` because the outer envelope is encrypted under
/// a key derived from the group key — we have to unseal before we can
/// compute the id from the inner body. Returns `None` if the bytes
/// aren't a valid sealed frame for a group the receiver is a member
/// of.
pub fn extract_message_id(gm: &GroupManager, wire: &[u8]) -> Option<[u8; 16]> {
    let (_, inner) = open_outer_envelope(wire, |gid| gm.export_group_key(gid)).ok()?;
    let envelope = GroupMessageEnvelope::from_inner_bincode(&inner).ok()?;
    Some(group_message_id(&envelope.body))
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
    let signature = sender_identity
        .sign(&payload)
        .context("sign group message")?;
    let envelope = GroupMessageEnvelope { body, signature };
    let inner_bincoded = envelope.to_inner_bincode()?;

    // Seal under the outer-envelope key so passive observers on the
    // gossipsub topic learn nothing beyond (group_id, message_size,
    // timestamp-of-arrival). `sender_id`, `generation`, the signature,
    // and the inner AEAD ciphertext are all encrypted by this layer.
    let group_key = gm
        .export_group_key(&group_id)
        .ok_or_else(|| anyhow!("encrypt: no group key installed"))?;
    seal_outer_envelope(&group_id, &group_key, &inner_bincoded)
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
    // Strip the outer-envelope layer first. Failure here (wrong magic,
    // wrong group, outer AEAD reject) means the frame either isn't ours
    // or has been tampered with — bounce it before any signature work.
    let (_outer_group_id, inner) = open_outer_envelope(wire, |gid| gm.export_group_key(gid))?;
    let envelope = GroupMessageEnvelope::from_inner_bincode(&inner)?;
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
    if !matches!(
        sender.member_status,
        crate::groups::group_manager::MemberStatus::Active
    ) {
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
