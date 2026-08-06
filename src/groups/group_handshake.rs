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
use crate::identity::identity_key::{HybridSignature, IdentityId, IdentityKey, IdentityKeyPair};
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
    /// The member's last-known libp2p PeerId (base58), distributed
    /// in-band so every member can direct-route to every other member
    /// (e.g. a promoted admin's key rotation) without learning peers
    /// from the gossip author. Empty for members enrolled before this
    /// field existed or whose PeerId the snapshot builder doesn't know;
    /// receivers ingest only non-empty values into their peer directory.
    /// Authenticated as part of the enclosing frame's signature.
    #[serde(default)]
    pub peer_id: String,
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
    /// The joiner's own libp2p PeerId (base58), self-attested and
    /// covered by the frame signature. The inviter routes the direct
    /// `JoinAccepted`/`JoinRejected` reply to this peer instead of
    /// reading it off the gossip author (`message.source`). Carrying it
    /// in the signed body makes the reply-routing linkage authenticated
    /// and removes the join handshake's dependency on gossipsub
    /// broadcasting the author PeerId — the prerequisite for switching
    /// group publishing to anonymous authorship. A joiner can only lie
    /// about *its own* address, which just misroutes its own reply.
    pub joiner_peer_id: String,
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

/// Broadcast component of a split key rotation, sent **only** when a
/// member was removed. Its sole job is to reach the *removed* member —
/// who gets no direct [`KeyDeliveryBody`] — so they learn they are out
/// and can wipe their per-group Kyber secret. It carries no key
/// material and, critically, never advances a receiver's generation on
/// its own: that stays lock-stepped to key installation, which only a
/// [`KeyDeliveryBody`] performs. Proactive rotations (no removal) send
/// no announce at all.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRotationAnnounceBody {
    pub group_id: GroupId,
    pub generation: u64,
    pub rotator_id: IdentityId,
    pub removed_member_id: IdentityId,
    pub timestamp: u64,
}

/// Directed component of a split key rotation: the new group key wrapped
/// to exactly one remaining member's Kyber pubkey, delivered off-topic
/// over `/qubee/direct/1`. This is the frame that atomically advances
/// the recipient's generation and installs the key. It also carries
/// `removed_member_id` so a recipient converges its roster from the
/// delivery alone, without depending on the broadcast announce.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDeliveryBody {
    pub group_id: GroupId,
    pub generation: u64,
    pub rotator_id: IdentityId,
    pub removed_member_id: Option<IdentityId>,
    pub recipient_id: IdentityId,
    pub wrapped_key: WrappedGroupKey,
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

/// Body of an `OwnershipTransfer` payload. The current `Owner`
/// (`donor_id`) hands the role to an existing member (`new_owner_id`)
/// and becomes `Admin`. Both role swaps are applied atomically by
/// receivers — there is never a wire-observable instant with two
/// owners or zero owners.
///
/// `new_version` carries the post-transfer `group.version`, mirroring
/// `RoleChangeBody`. The strict generation gate in
/// `decrypt_group_message` needs receivers to track the donor's view.
///
/// The new_owner must already be an active group member at the donor's
/// view; transferring to a non-member or a removed member is rejected
/// at sign time. Recipients re-verify this against their own local
/// view, so a concurrent removal that strands the transfer arrives
/// as a no-op (handler returns Err and the signed frame is dropped).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnershipTransferBody {
    pub group_id: GroupId,
    pub donor_id: IdentityId,
    pub new_owner_id: IdentityId,
    pub new_version: u64,
    pub timestamp: u64,
}

/// Body of a `MessageAck` payload. Acks a single delivered group
/// message back to the sender + every other group member via the
/// gossipsub topic. `message_id` is the 16-byte BLAKE3 truncation
/// from `group_message::group_message_id` over the canonical body
/// bytes — both sender and acker compute the same id deterministically,
/// so no explicit id field rides the message envelope.
///
/// Acks are advisory: a missing ack just means the sender's local
/// `MessageStatus` stays at `SENT`. Late + duplicate acks are
/// idempotent — receivers (the original sender, plus everyone else
/// listening) ignore acks for unknown message ids and dedupe acks
/// with the same `(message_id, acker_id)` pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageAckBody {
    pub group_id: GroupId,
    pub message_id: [u8; 16],
    pub acker_id: IdentityId,
    pub timestamp: u64,
}

/// Public prekey bundle for the 1:1 ratchet, self-signed by the
/// publisher's hybrid identity key. The signature (over
/// [`canonical_prekey_bundle`]) attests "the holder of `publisher`
/// published these prekeys" — it binds the ephemeral prekeys to the
/// long-term identity **without** making any later message
/// non-repudiable (messages are authenticated by the ratchet, not by
/// this key).
///
/// The `publisher` field carries the full `IdentityKey` so a receiver
/// can verify the signature standalone (trust in the identity itself
/// still comes from the normal contact/verification flow).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrekeyBundleBody {
    pub publisher: IdentityKey,
    /// X25519 identity DH public (deniable handshake; distinct from the
    /// Ed25519/ML-DSA signing identity in `publisher`).
    pub identity_x25519: [u8; 32],
    /// X25519 signed prekey public (also the initial ratchet public).
    pub signed_prekey: [u8; 32],
    /// Optional one-time prekey public (single-use forward secrecy for
    /// the very first message).
    pub one_time_prekey: Option<[u8; 32]>,
    /// ML-KEM-768 prekey public bytes.
    pub kem_public: Vec<u8>,
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
    /// The current group symmetric key, KEM-wrapped under the
    /// requester's per-group Kyber pubkey (looked up from the
    /// responder's local view of the requester). `None` when the
    /// responder doesn't have a Kyber pubkey for the requester
    /// (legacy enrolment, snapshot drift) — receivers fall back
    /// to whatever key they already had, accepting that they
    /// stay out of band on group messages encrypted with the
    /// fresh key.
    ///
    /// Closes the receive-decrypt gap that the rev-4 P1
    /// `RequestStateSync` flow left open: a member who missed a
    /// `MemberAdded` *and* a `KeyRotation` previously got their
    /// roster + version back, but bounced on the strict
    /// generation gate in `decrypt_group_message` because their
    /// local key was stale.
    pub wrapped_group_key: Option<WrappedGroupKey>,
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
    OwnershipTransfer {
        body: OwnershipTransferBody,
        signature: HybridSignature,
    },
    MessageAck {
        body: MessageAckBody,
        signature: HybridSignature,
    },
    /// Identity-level (not group-level) frame: a peer's published
    /// prekey bundle for the forward-secret/deniable 1:1 ratchet
    /// (Stage 2). Published on the global topic, self-signed by the
    /// publisher's hybrid identity key; receivers verify + cache it.
    /// Not consumed by send/receive yet.
    PrekeyBundle {
        body: PrekeyBundleBody,
        signature: HybridSignature,
    },
    // NOTE: `to_wire` bincodes this enum, which tags variants by their
    // *position*. New variants MUST be appended here (never inserted
    // mid-enum) or every later variant's wire tag shifts and old peers
    // misdecode existing frames.
    /// Broadcast half of a split rotation (removal notice for the removed
    /// member; see [`KeyRotationAnnounceBody`]).
    KeyRotationAnnounce {
        body: KeyRotationAnnounceBody,
        signature: HybridSignature,
    },
    /// Directed half of a split rotation (one recipient's wrapped key;
    /// see [`KeyDeliveryBody`]). Delivered off-topic, one per member.
    KeyDelivery {
        body: KeyDeliveryBody,
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
        // Bounded decode: this runs on unauthenticated gossip bytes,
        // *before* any signature check, so a crafted length prefix must
        // not drive an oversized allocation.
        bounded_bincode_deserialize(&bytes[HANDSHAKE_MAGIC.len()..]).ok()
    }
}

/// Upper bound on a single decoded wire frame. Comfortably above the
/// largest legitimate handshake (a `JoinAccepted` / `StateSyncResponse`
/// snapshotting up to `QUBEE_MAX_GROUP_MEMBERS` members — each with an
/// ML-DSA-44 pubkey ~1312 B + ML-KEM-768 pubkey ~1184 B — plus a
/// wrapped group key), and far below any allocation that would matter
/// as a DoS. libp2p's gossipsub `max_transmit_size` is the outer bound;
/// this is the inner, encoding-aware one.
pub(crate) const MAX_WIRE_FRAME_BYTES: u64 = 512 * 1024;

/// `bincode::deserialize` with a size limit, matching the fixint /
/// little-endian / reject-trailing config the top-level
/// `bincode::serialize` uses to *write* these frames (so encoding
/// stays byte-compatible) while capping the maximum allocation.
pub(crate) fn bounded_bincode_deserialize<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_WIRE_FRAME_BYTES)
        .deserialize(bytes)
        .map_err(|e| anyhow!("bounded bincode decode: {e}"))
}

// ---------------------------------------------------------------------------
// Canonical signing payloads
// ---------------------------------------------------------------------------
//
// Each handshake variant signs a deterministic byte string built from
// (a) the variant body and (b) a domain-separation tag. We don't sign
// the bincode of the variant itself because bincode is not
// canonical (HashMap iteration order, struct field reordering, …).

// _v2: the body grew a `joiner_peer_id` so the inviter can route the
// direct JoinAccepted reply from the authenticated frame instead of the
// gossip author. Old-tag devices fail signature verification on the new
// bytes (and vice versa) — a deliberate wire bump, not enforcement.
const REQUEST_JOIN_TAG: &[u8] = b"qubee_handshake_request_join_v2";
// _v3 because GroupMemberSummary now carries `peer_id` (in-band member
// PeerId distribution for gossip-independent direct routing). It was _v2
// when the summary grew kyber_pub in plan revision 2 priority 5b. Every
// frame that bincode-serialises a summary (JoinAccepted / MemberAdded /
// StateSyncResponse) bumps together for the same reason.
const JOIN_ACCEPTED_TAG: &[u8] = b"qubee_handshake_join_accepted_v3";
const JOIN_REJECTED_TAG: &[u8] = b"qubee_handshake_join_rejected_v1";
const KEY_ROTATION_TAG: &[u8] = b"qubee_handshake_key_rotation_v1";
const KEY_ROTATION_ANNOUNCE_TAG: &[u8] = b"qubee_handshake_key_rotation_announce_v1";
const KEY_DELIVERY_TAG: &[u8] = b"qubee_handshake_key_delivery_v1";
// _v2: GroupMemberSummary grew `peer_id` (in-band member PeerId
// distribution) — the new_member summary bincodes into these bytes.
const MEMBER_ADDED_TAG: &[u8] = b"qubee_handshake_member_added_v2";
const ROLE_CHANGE_TAG: &[u8] = b"qubee_handshake_role_change_v1";
const OWNERSHIP_TRANSFER_TAG: &[u8] = b"qubee_handshake_ownership_transfer_v1";
const MESSAGE_ACK_TAG: &[u8] = b"qubee_handshake_message_ack_v1";
const PREKEY_BUNDLE_TAG: &[u8] = b"qubee_handshake_prekey_bundle_v1";

/// Validity window for a published prekey bundle. Generous (30 days)
/// because a bundle is meant to be reused across many handshakes until
/// the publisher rotates it — unlike the 5-minute handshake window,
/// freshness here is enforced by rotation, not by the signature age.
pub const PREKEY_BUNDLE_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;
const REQUEST_STATE_SYNC_TAG: &[u8] = b"qubee_handshake_request_state_sync_v1";
// _v3: GroupMemberSummary grew `peer_id` (in-band member PeerId
// distribution) — every roster row bincodes into these bytes. It was
// _v2 when the body grew an `Option<WrappedGroupKey>` for KeyRotation
// re-send (rev-4 P1 resync flow). Devices on an older tag fail signature
// verification on the new bytes — a labeling correction, not enforcement.
const STATE_SYNC_RESPONSE_TAG: &[u8] = b"qubee_handshake_state_sync_response_v3";

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
    out.push(0u8);
    out.extend_from_slice(&(body.joiner_peer_id.len() as u32).to_le_bytes());
    out.extend_from_slice(body.joiner_peer_id.as_bytes());
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
    // Wrapped group key is optional. Frame it with a 1-byte tag
    // (0 = absent, 1 = present) followed by the wrapped struct's
    // length-prefixed fields. Same shape the `KeyRotationBody`
    // canonical bytes use for each delivery — keeps the
    // serialisation pattern consistent across handshake variants.
    if let Some(wrapped) = &body.wrapped_group_key {
        out.push(1u8);
        out.extend_from_slice(&(wrapped.kem_ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&wrapped.kem_ciphertext);
        out.extend_from_slice(&wrapped.nonce);
        out.extend_from_slice(&(wrapped.wrapped_key.len() as u32).to_le_bytes());
        out.extend_from_slice(&wrapped.wrapped_key);
    } else {
        out.push(0u8);
    }
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

pub fn canonical_ownership_transfer(body: &OwnershipTransferBody) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(OWNERSHIP_TRANSFER_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.donor_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.new_owner_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.new_version.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    Ok(out)
}

pub fn canonical_message_ack(body: &MessageAckBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(MESSAGE_ACK_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.message_id);
    out.push(0u8);
    out.extend_from_slice(body.acker_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    out
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

pub fn canonical_key_rotation_announce(body: &KeyRotationAnnounceBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(KEY_ROTATION_ANNOUNCE_TAG);
    out.push(0u8);
    out.extend_from_slice(body.group_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.generation.to_le_bytes());
    out.push(0u8);
    out.extend_from_slice(body.rotator_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(body.removed_member_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    out
}

pub fn canonical_key_delivery(body: &KeyDeliveryBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(KEY_DELIVERY_TAG);
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
    out.extend_from_slice(body.recipient_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&(body.wrapped_key.kem_ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.wrapped_key.kem_ciphertext);
    out.extend_from_slice(&body.wrapped_key.nonce);
    out.extend_from_slice(&(body.wrapped_key.wrapped_key.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.wrapped_key.wrapped_key);
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    out
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
pub fn verify_request_join(body: &RequestJoinBody, signature: &HybridSignature) -> Result<bool> {
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

/// Sign a `KeyRotationAnnounce` (broadcast removal notice).
pub fn sign_key_rotation_announce(
    keypair: &IdentityKeyPair,
    body: KeyRotationAnnounceBody,
) -> Result<GroupHandshake> {
    let payload = canonical_key_rotation_announce(&body);
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::KeyRotationAnnounce { body, signature })
}

/// Verify a `KeyRotationAnnounce` against the rotator's stated key.
pub fn verify_key_rotation_announce(
    body: &KeyRotationAnnounceBody,
    signature: &HybridSignature,
    expected_rotator: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_key_rotation_announce(body);
    expected_rotator.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Sign a `KeyDelivery` (directed per-recipient wrapped key).
pub fn sign_key_delivery(
    keypair: &IdentityKeyPair,
    body: KeyDeliveryBody,
) -> Result<GroupHandshake> {
    let payload = canonical_key_delivery(&body);
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::KeyDelivery { body, signature })
}

/// Verify a `KeyDelivery` against the rotator's stated key.
pub fn verify_key_delivery(
    body: &KeyDeliveryBody,
    signature: &HybridSignature,
    expected_rotator: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_key_delivery(body);
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
pub fn sign_role_change(keypair: &IdentityKeyPair, body: RoleChangeBody) -> Result<GroupHandshake> {
    let payload = canonical_role_change(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::RoleChange { body, signature })
}

/// Sign a `MessageAck` payload with the acker's keypair. Auto-fired
/// by every receiver immediately after a successful
/// `decrypt_group_message`; the sender + every other group member
/// see it on the group's gossipsub topic.
pub fn sign_message_ack(keypair: &IdentityKeyPair, body: MessageAckBody) -> Result<GroupHandshake> {
    let payload = canonical_message_ack(&body);
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::MessageAck { body, signature })
}

/// Verify a `MessageAck` against the stated acker's `IdentityKey`.
/// The handler is responsible for confirming the acker is still an
/// active member of the group; this only verifies cryptographic
/// authorship and freshness.
pub fn verify_message_ack(
    body: &MessageAckBody,
    signature: &HybridSignature,
    expected_acker: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_message_ack(body);
    expected_acker.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
}

/// Canonical signing bytes for a prekey bundle. Length-prefixed +
/// domain-tagged so the signature is unambiguous.
pub fn canonical_prekey_bundle(body: &PrekeyBundleBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + body.kem_public.len());
    out.extend_from_slice(PREKEY_BUNDLE_TAG);
    out.push(0u8);
    out.extend_from_slice(body.publisher.identity_id.as_ref());
    out.push(0u8);
    out.extend_from_slice(&body.identity_x25519);
    out.push(0u8);
    out.extend_from_slice(&body.signed_prekey);
    out.push(0u8);
    // one_time_prekey: 1-byte present flag then (optional) 32 bytes.
    match &body.one_time_prekey {
        Some(otp) => {
            out.push(1u8);
            out.extend_from_slice(otp);
        }
        None => out.push(0u8),
    }
    out.push(0u8);
    out.extend_from_slice(&(body.kem_public.len() as u32).to_le_bytes());
    out.extend_from_slice(&body.kem_public);
    out.push(0u8);
    out.extend_from_slice(&body.timestamp.to_le_bytes());
    out
}

/// Sign a prekey bundle with the publisher's hybrid identity keypair.
/// The `body.publisher` must be the public half of `keypair`.
pub fn sign_prekey_bundle(
    keypair: &IdentityKeyPair,
    body: PrekeyBundleBody,
) -> Result<GroupHandshake> {
    let payload = canonical_prekey_bundle(&body);
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::PrekeyBundle { body, signature })
}

/// Verify a prekey bundle: the signature must be by `body.publisher`
/// and within [`PREKEY_BUNDLE_MAX_AGE_SECS`]. Returns `true` on a valid,
/// fresh, self-consistent bundle.
pub fn verify_prekey_bundle(body: &PrekeyBundleBody, signature: &HybridSignature) -> Result<bool> {
    let payload = canonical_prekey_bundle(body);
    body.publisher
        .verify_with_max_age(&payload, signature, PREKEY_BUNDLE_MAX_AGE_SECS)
}

/// Sign an `OwnershipTransfer` payload with the donor's keypair.
/// Donor must be the current `Owner`; the API in `GroupManager`
/// enforces that gate before producing the body.
pub fn sign_ownership_transfer(
    keypair: &IdentityKeyPair,
    body: OwnershipTransferBody,
) -> Result<GroupHandshake> {
    let payload = canonical_ownership_transfer(&body)?;
    let signature = keypair.sign(&payload)?;
    Ok(GroupHandshake::OwnershipTransfer { body, signature })
}

/// Verify an `OwnershipTransfer` against the stated donor's
/// `IdentityKey`. The handler is responsible for confirming the
/// donor was the group's `Owner` at signing time; this only
/// verifies cryptographic authorship and freshness.
pub fn verify_ownership_transfer(
    body: &OwnershipTransferBody,
    signature: &HybridSignature,
    expected_donor: &IdentityKey,
) -> Result<bool> {
    let payload = canonical_ownership_transfer(body)?;
    expected_donor.verify_with_max_age(&payload, signature, HANDSHAKE_MAX_AGE_SECS)
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
            joiner_peer_id: "12D3KooWBob".to_string(),
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
    fn request_join_peer_id_is_authenticated() {
        // The joiner's PeerId rides in the signed body; tampering with it
        // must break verification — otherwise an attacker could redirect
        // the inviter's direct JoinAccepted (with the wrapped group key)
        // to a peer of their choosing while the rest of the body verifies.
        let (kp, body) = fresh_request_join();
        let signed = sign_request_join(&kp, body).unwrap();
        if let GroupHandshake::RequestJoin {
            mut body,
            signature,
        } = signed
        {
            assert!(verify_request_join(&body, &signature).unwrap());
            body.joiner_peer_id = "12D3KooWMallory".to_string();
            assert!(!verify_request_join(&body, &signature).unwrap());
        } else {
            panic!("wrong variant");
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

    #[test]
    fn oversized_length_prefix_is_rejected_not_allocated() {
        // A fixint-bincode `Vec<u8>` starts with an 8-byte length. Craft
        // a frame claiming u64::MAX elements: the bounded decoder must
        // reject on the size limit rather than attempt a ~16 EB
        // allocation. (Unbounded `bincode::deserialize` would try.)
        let mut evil = Vec::new();
        evil.extend_from_slice(&u64::MAX.to_le_bytes()); // claimed length
                                                         // no payload follows
        let decoded: Result<Vec<u8>> = bounded_bincode_deserialize(&evil);
        assert!(
            decoded.is_err(),
            "a frame with an oversized length prefix must be rejected",
        );

        // Sanity: a legitimately-sized value still round-trips through
        // the bounded decoder.
        let ok: Vec<u8> = vec![1, 2, 3, 4, 5];
        let bytes = bincode::serialize(&ok).unwrap();
        let back: Vec<u8> = bounded_bincode_deserialize(&bytes).unwrap();
        assert_eq!(ok, back);
    }
}
