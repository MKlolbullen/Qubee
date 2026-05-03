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

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768::{
    decapsulate as kyber_decapsulate, encapsulate as kyber_encapsulate, keypair as kyber_keypair,
    Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SecretKey as KyberSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::groups::group_manager::GroupId;
use crate::groups::group_permissions::Role;
use crate::identity::identity_key::{
    HybridSignature, IdentityId, IdentityKey, IdentityKeyPair,
};
use crate::security::secure_rng;

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
///
/// `kyber_pub` carries the member's *long-lived* per-group Kyber pubkey.
/// Without it, a joiner's local snapshot of the existing members ends
/// up with empty Kyber keys, so any rotation the joiner later plans
/// silently delivers to nobody (closes the A2 bug — see plan revision
/// 2 priority 5b).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMemberSummary {
    pub identity_id: IdentityId,
    pub identity_key: IdentityKey,
    pub display_name: String,
    pub role: Role,
    pub joined_at: u64,
    pub kyber_pub: Vec<u8>,
}

/// Body of a `RequestJoin` payload that gets bundled into the wire
/// envelope and signed end-to-end. Pulling it out of the enum lets us
/// hash the canonical bytes deterministically.
///
/// `joiner_kyber_pub` carries an *ephemeral* Kyber-768 public key the
/// joiner generates fresh for this handshake; the inviter encapsulates
/// the group key under it inside [`JoinAcceptedBody::wrapped_group_key`].
/// The matching ephemeral secret is held in process memory by the
/// joiner until the inviter's reply lands, then dropped — that gives
/// us forward secrecy on the group-key transport even if the joiner's
/// long-term identity is later compromised.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestJoinBody {
    pub group_id: GroupId,
    pub invitation_code: String,
    pub joiner_public_key: IdentityKey,
    pub joiner_display_name: String,
    pub joiner_kyber_pub: Vec<u8>,
}

/// Group symmetric key wrapped to a single recipient via Kyber-768
/// KEM + ChaCha20-Poly1305. The KEM produces a shared secret that we
/// HKDF-derive a wrap key from; the wrap key encrypts the actual
/// 32-byte group key. This split lets us rotate the group key without
/// re-doing the KEM per recipient and keeps the KEM secret out of any
/// per-message calculation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedGroupKey {
    /// Output of `pqcrypto_mlkem::mlkem768::encapsulate(joiner_pub)`.
    pub kem_ciphertext: Vec<u8>,
    /// AEAD nonce for the wrapped key.
    pub nonce: [u8; 12],
    /// `ChaCha20Poly1305(key=HKDF(kem_ss, "qubee_group_wrap_v1"), nonce)`
    /// over the 32-byte plaintext group key.
    pub wrapped_key: Vec<u8>,
}

const GROUP_KEY_WRAP_INFO: &[u8] = b"qubee_group_wrap_v1";

impl WrappedGroupKey {
    /// Wrap a 32-byte group key for a single recipient using their
    /// ephemeral Kyber-768 public key.
    pub fn wrap(group_key: &[u8; 32], joiner_kyber_pub: &[u8]) -> Result<Self> {
        let pk = KyberPublicKey::from_bytes(joiner_kyber_pub)
            .map_err(|e| anyhow!("invalid joiner Kyber pubkey: {e}"))?;
        let (shared_secret, ciphertext) = kyber_encapsulate(&pk);

        let wrap_key = derive_wrap_key(shared_secret.as_bytes())?;
        let cipher = ChaCha20Poly1305::new((&wrap_key).into());
        let nonce_bytes = secure_rng::random::array::<12>()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let wrapped_key = cipher
            .encrypt(nonce, group_key.as_ref())
            .map_err(|e| anyhow!("group key wrap failed: {e}"))?;

        Ok(WrappedGroupKey {
            kem_ciphertext: ciphertext.as_bytes().to_vec(),
            nonce: nonce_bytes,
            wrapped_key,
        })
    }

    /// Inverse of [`wrap`]. The Kyber secret is consumed (and zeroised
    /// when the slice is dropped by the caller) so accidental reuse is
    /// harder.
    pub fn unwrap(&self, joiner_kyber_secret: &[u8]) -> Result<[u8; 32]> {
        let sk = KyberSecretKey::from_bytes(joiner_kyber_secret)
            .map_err(|e| anyhow!("invalid joiner Kyber secret: {e}"))?;
        let ct = KyberCiphertext::from_bytes(&self.kem_ciphertext)
            .map_err(|e| anyhow!("invalid KEM ciphertext: {e}"))?;
        let shared_secret = kyber_decapsulate(&ct, &sk);

        let wrap_key = derive_wrap_key(shared_secret.as_bytes())?;
        let cipher = ChaCha20Poly1305::new((&wrap_key).into());
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(nonce, self.wrapped_key.as_ref())
            .map_err(|e| anyhow!("group key unwrap failed: {e}"))?;
        if plaintext.len() != 32 {
            return Err(anyhow!("unwrapped group key has wrong length"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plaintext);
        Ok(out)
    }
}

fn derive_wrap_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(GROUP_KEY_WRAP_INFO, &mut out)
        .map_err(|e| anyhow!("HKDF expand: {e}"))?;
    Ok(out)
}

/// Generate a fresh ephemeral Kyber-768 keypair for use in a single
/// `RequestJoin` exchange. Returned as raw bytes so the caller can
/// stash the secret in a transient cache.
pub fn generate_ephemeral_kyber() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber_keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
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
    /// Group encryption key wrapped to the joiner's ephemeral Kyber-768
    /// public key from the matching `RequestJoinBody`.
    pub wrapped_group_key: WrappedGroupKey,
    /// Inviter's view of `group.version` at the moment the join lands.
    /// The joiner adopts this verbatim so subsequent generation-counter
    /// gates (`decrypt_group_message`, `process_key_rotation`) line up
    /// across the two devices. Without this the joiner starts at
    /// `version = 1` while the inviter is at N>1, and every
    /// post-join group message bounces on "generation mismatch".
    pub snapshot_version: u64,
}

/// Body of a `JoinRejected` payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinRejectedBody {
    pub group_id: GroupId,
    pub invitation_code: String,
    pub joiner_id: IdentityId,
    pub reason: String,
}

/// One entry of a `KeyRotation` payload — the new group key wrapped
/// to a single recipient's long-lived Kyber pubkey.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberKeyDelivery {
    pub recipient_id: IdentityId,
    pub wrapped_key: WrappedGroupKey,
}

/// Body of a `KeyRotation` payload. Sent by the group owner (or any
/// member with `Permission::RemoveMembers`) when a member is removed
/// or leaves, so the remaining members converge on a fresh group key
/// the departed member can no longer decrypt with.
///
/// `removed_member_id` is `None` for proactive rotations (e.g. on a
/// timer or after a key compromise the owner suspects).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRotationBody {
    pub group_id: GroupId,
    /// Monotonically increasing counter; receivers ignore rotations
    /// older than the highest generation they've already seen.
    pub generation: u64,
    pub rotator_id: IdentityId,
    pub removed_member_id: Option<IdentityId>,
    pub deliveries: Vec<MemberKeyDelivery>,
    /// Unix timestamp; receivers reject rotations older than
    /// [`HANDSHAKE_MAX_AGE_SECS`] to bound replay window.
    pub timestamp: u64,
}

/// Body of a `MemberAdded` payload. Inviters broadcast this to the
/// group topic immediately after a successful `RequestJoin` so that
/// existing members learn about the late joiner — including the late
/// joiner's per-group Kyber pubkey, which is the only way subsequent
/// rotations from existing members can deliver to the new joiner
/// (closes A2; see plan revision 2 priority 5b).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberAddedBody {
    pub group_id: GroupId,
    pub adder_id: IdentityId,
    pub new_member: GroupMemberSummary,
    /// The inviter's `group.version` immediately after enrolling the
    /// new member (i.e. after `add_member` + `set_member_kyber_pub`).
    /// Receivers install this verbatim so the strict generation gate
    /// in `decrypt_group_message` doesn't bounce subsequent messages
    /// from the inviter on a stale local view.
    pub new_version: u64,
    pub timestamp: u64,
}

/// Body of a `RoleChange` payload. An owner promotes (or demotes) a
/// member; existing members apply the change to their local view so
/// downstream permission checks (rotation broadcasts from a promoted
/// admin, etc.) line up. `new_version` rides along for the same reason
/// it does on `MemberAddedBody` — the strict generation gate in
/// `decrypt_group_message` needs receiver version to track promoter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleChangeBody {
    pub group_id: GroupId,
    pub promoter_id: IdentityId,
    pub member_id: IdentityId,
    pub new_role: Role,
    pub new_version: u64,
    pub timestamp: u64,
}

/// Body of a `RequestStateSync` payload. A member who's been offline
/// through one or more `MemberAdded` / `RoleChange` broadcasts uses
/// this to ask any current member of the group for the latest
/// roster + version. The responder verifies the requester is still
/// an active member of the group, then signs and broadcasts a
/// matching `StateSyncResponseBody` — gossipsub delivers the reply
/// to anyone subscribed to the group topic, and the requester
/// merges the snapshot into local state.
///
/// `since_version` is informational; the responder always sends the
/// full current snapshot rather than a delta. Snapshots are bounded
/// by the 16-member group cap, so the bandwidth waste is small and
/// the implementation stays simpler than reorder-safe deltas.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestStateSyncBody {
    pub group_id: GroupId,
    pub requester_id: IdentityId,
    pub since_version: u64,
    pub timestamp: u64,
}

/// Body of a `StateSyncResponse` payload. Reply to a
/// `RequestStateSync`; carries the responder's current view of the
/// group (members + version) so the requester can converge.
///
/// Group-key rotation re-send is intentionally NOT bundled here.
/// The requester learns about new members and role changes; if
/// they've also missed a `KeyRotation` they'll need a separate
/// catch-up flow that re-encapsulates the current key under their
/// Kyber pubkey (post-rev-4 work). Until that lands, a member who
/// missed both will see a fresh roster but bounce on the strict
/// generation gate when they try to decrypt — at which point a
/// human-driven re-join is the recovery path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSyncResponseBody {
    pub group_id: GroupId,
    pub responder_id: IdentityId,
    pub requester_id: IdentityId,
    pub members: Vec<GroupMemberSummary>,
    pub current_version: u64,
    pub timestamp: u64,
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
    KeyRotation {
        body: KeyRotationBody,
        signature: HybridSignature,
    },
    MemberAdded {
        body: MemberAddedBody,
        signature: HybridSignature,
    },
    RoleChange {
        body: RoleChangeBody,
        signature: HybridSignature,
    },
    RequestStateSync {
        body: RequestStateSyncBody,
        signature: HybridSignature,
    },
    StateSyncResponse {
        body: StateSyncResponseBody,
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
// _v2 because GroupMemberSummary now carries kyber_pub — the canonical
// bytes of every JoinAccepted body changed in plan revision 2 priority
// 5b. Other handshake tags didn't grow new fields and stay at _v1.
const JOIN_ACCEPTED_TAG: &[u8] = b"qubee_handshake_join_accepted_v2";
const JOIN_REJECTED_TAG: &[u8] = b"qubee_handshake_join_rejected_v1";
const KEY_ROTATION_TAG: &[u8] = b"qubee_handshake_key_rotation_v1";
const MEMBER_ADDED_TAG: &[u8] = b"qubee_handshake_member_added_v1";
const ROLE_CHANGE_TAG: &[u8] = b"qubee_handshake_role_change_v1";
const REQUEST_STATE_SYNC_TAG: &[u8] = b"qubee_handshake_request_state_sync_v1";
const STATE_SYNC_RESPONSE_TAG: &[u8] = b"qubee_handshake_state_sync_response_v1";

pub fn canonical_request_join(body: &RequestJoinBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(REQUEST_JOIN_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.invitation_code.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&bincode::serialize(&body.joiner_public_key)?);
    out.push(0u8);
    out.extend_from_slice(body.joiner_display_name.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&(body.joiner_kyber_pub.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.joiner_kyber_pub);
    Ok(out)
}

pub fn canonical_join_accepted(body: &JoinAcceptedBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2048);
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
    out.push(0u8);
    // Authenticate the wrapped group key — without this an attacker
    // could swap the KEM ciphertext for one wrapping a key they
    // control, while the rest of the body verifies fine.
    out.extend_from_slice(&(body.wrapped_group_key.kem_ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.wrapped_group_key.kem_ciphertext);
    out.extend_from_slice(&body.wrapped_group_key.nonce);
    out.extend_from_slice(&(body.wrapped_group_key.wrapped_key.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.wrapped_group_key.wrapped_key);
    out.push(0u8);
    out.extend_from_slice(&body.snapshot_version.to_le_bytes());
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

pub fn canonical_request_state_sync(body: &RequestStateSyncBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(REQUEST_STATE_SYNC_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.requester_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.since_version.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    Ok(out)
}

pub fn canonical_state_sync_response(body: &StateSyncResponseBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(STATE_SYNC_RESPONSE_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.responder_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.requester_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&(body.members.len() as u32).to_le_bytes());
    for m in &body.members {
        out.extend_from_slice(&bincode::serialize(m)?);
    }
    out.push(0u8);
    out.extend_from_slice(&body.current_version.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    Ok(out)
}

pub fn canonical_role_change(body: &RoleChangeBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(ROLE_CHANGE_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.promoter_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.member_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&bincode::serialize(&body.new_role)?);
    out.push(0u8);
    out.extend_from_slice(&body.new_version.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    Ok(out)
}

pub fn canonical_member_added(body: &MemberAddedBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(MEMBER_ADDED_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.adder_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&bincode::serialize(&body.new_member)?);
    out.push(0u8);
    out.extend_from_slice(&body.new_version.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    Ok(out)
}

pub fn canonical_key_rotation(body: &KeyRotationBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(KEY_ROTATION_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.generation.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(body.rotator_id.as_ref());
    out.push(0u8);
    if let Some(removed) = body.removed_member_id {
        out.push(1u8);
        out.extend_from_slice(removed.as_ref());
    } else {
        out.push(0u8);
    }
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&(body.deliveries.len() as u32).to_le_bytes());
    for d in &body.deliveries {
        out.extend_from_slice(d.recipient_id.as_ref());
        out.extend_from_slice(&(d.wrapped_key.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&d.wrapped_key.kem_ciphertext);
        out.extend_from_slice(&d.wrapped_key.nonce);
        out.extend_from_slice(&(d.wrapped_key.wrapped_key.len() as u32).to_le_bytes());
        out.extend_from_slice(&d.wrapped_key.wrapped_key);
    }
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

/// Sign a `KeyRotation` payload with the rotator's identity keypair.
pub fn sign_key_rotation(
    keypair: &IdentityKeyPair,
    body: KeyRotationBody,
) -> Result<GroupHandshake> {
    let payload = canonical_key_rotation(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::KeyRotation { body, signature })
}

/// Verify a `KeyRotation` against the rotator's stated `IdentityKey`.
/// The caller is responsible for pulling the rotator's pubkey out of
/// the local group state — receivers should reject rotations from
/// keys that aren't actually members with rotation permission.
pub fn verify_key_rotation(
    body: &KeyRotationBody,
    signature: &HybridSignature,
    expected_rotator: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_key_rotation(body)?;
    expected_rotator.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Sign a `MemberAdded` payload with the adder's (inviter's) keypair.
pub fn sign_member_added(
    keypair: &IdentityKeyPair,
    body: MemberAddedBody,
) -> Result<GroupHandshake> {
    let payload = canonical_member_added(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::MemberAdded { body, signature })
}

/// Verify a `MemberAdded` against the adder's stated `IdentityKey`.
/// Callers must check separately that the adder is actually a member
/// with `Permission::AddMembers` in the local view of the group; this
/// only verifies cryptographic authorship and freshness.
pub fn verify_member_added(
    body: &MemberAddedBody,
    signature: &HybridSignature,
    expected_adder: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_member_added(body)?;
    expected_adder.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Sign a `RoleChange` payload with the promoter's keypair.
pub fn sign_role_change(
    keypair: &IdentityKeyPair,
    body: RoleChangeBody,
) -> Result<GroupHandshake> {
    let payload = canonical_role_change(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::RoleChange { body, signature })
}

/// Sign a `RequestStateSync` payload with the requester's keypair.
pub fn sign_request_state_sync(
    keypair: &IdentityKeyPair,
    body: RequestStateSyncBody,
) -> Result<GroupHandshake> {
    let payload = canonical_request_state_sync(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::RequestStateSync { body, signature })
}

/// Verify a `RequestStateSync` against the requester's stated
/// `IdentityKey`. The handler is responsible for confirming the
/// requester is still an active member of the group; this only
/// verifies cryptographic authorship and freshness.
pub fn verify_request_state_sync(
    body: &RequestStateSyncBody,
    signature: &HybridSignature,
    expected_requester: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_request_state_sync(body)?;
    expected_requester.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Sign a `StateSyncResponse` payload with the responder's keypair.
pub fn sign_state_sync_response(
    keypair: &IdentityKeyPair,
    body: StateSyncResponseBody,
) -> Result<GroupHandshake> {
    let payload = canonical_state_sync_response(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::StateSyncResponse { body, signature })
}

/// Verify a `StateSyncResponse` against the responder's stated
/// `IdentityKey`. The handler is responsible for confirming the
/// responder was an active member of the group at the version
/// returned in the snapshot; this only verifies cryptographic
/// authorship and freshness.
pub fn verify_state_sync_response(
    body: &StateSyncResponseBody,
    signature: &HybridSignature,
    expected_responder: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_state_sync_response(body)?;
    expected_responder.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Verify a `RoleChange` against the promoter's stated `IdentityKey`.
/// Callers must separately check that the promoter is actually the
/// owner of the local view of the group; this only verifies
/// cryptographic authorship and freshness.
pub fn verify_role_change(
    body: &RoleChangeBody,
    signature: &HybridSignature,
    expected_promoter: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_role_change(body)?;
    expected_promoter.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_request_join() -> (IdentityKeyPair, RequestJoinBody) {
        let kp = IdentityKeyPair::generate().unwrap();
        let (kyber_pub, _kyber_secret) = generate_ephemeral_kyber();
        let body = RequestJoinBody {
            group_id: GroupId::from_bytes([9u8; 32]),
            invitation_code: "abc".to_string(),
            joiner_public_key: kp.public_key(),
            joiner_display_name: "Bob".to_string(),
            joiner_kyber_pub: kyber_pub,
        };
        (kp, body)
    }

    #[test]
    fn wrapped_group_key_round_trip() {
        let (pk, sk) = generate_ephemeral_kyber();
        let key = [42u8; 32];
        let wrapped = WrappedGroupKey::wrap(&key, &pk).unwrap();
        let unwrapped = wrapped.unwrap(&sk).unwrap();
        assert_eq!(key, unwrapped);
    }

    #[test]
    fn wrapped_group_key_rejects_wrong_secret() {
        let (pk, _sk1) = generate_ephemeral_kyber();
        let (_pk2, sk2) = generate_ephemeral_kyber();
        let wrapped = WrappedGroupKey::wrap(&[7u8; 32], &pk).unwrap();
        assert!(wrapped.unwrap(&sk2).is_err());
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
