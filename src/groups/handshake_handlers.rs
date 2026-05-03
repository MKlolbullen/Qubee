//! Pure-function handshake orchestration, decoupled from the JNI
//! global mutexes so tests (and any future non-Android caller) can
//! exercise the protocol against ordinary [`GroupManager`] +
//! [`IdentityKeyPair`] values.
//!
//! The JNI integration in `jni_api.rs` is a thin wrapper over these
//! functions — it pulls state out of `lazy_static!`, calls into here,
//! then publishes the result on gossipsub.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::groups::group_handshake::{
    sign_join_accepted, sign_join_rejected, sign_key_rotation, sign_member_added,
    sign_state_sync_response, verify_join_accepted, verify_key_rotation, verify_member_added,
    verify_request_join, verify_request_state_sync, verify_role_change,
    verify_state_sync_response, GroupHandshake, GroupMemberSummary, JoinAcceptedBody,
    JoinRejectedBody, KeyRotationBody, MemberAddedBody, MemberKeyDelivery, RequestJoinBody,
    RequestStateSyncBody, RoleChangeBody, StateSyncResponseBody, WrappedGroupKey,
};
use crate::groups::group_manager::{GroupId, GroupManager, GroupMember, MemberStatus};
use crate::groups::group_permissions::{Permission, Role};
use crate::identity::identity_key::{HybridSignature, IdentityId, IdentityKey, IdentityKeyPair};

/// What the inviter wants to publish back after handling a `RequestJoin`.
#[derive(Debug)]
pub enum HandshakeOutcome {
    /// Joiner enrolled successfully. The caller should publish:
    ///   1. `body` + `signature` as the `JoinAccepted` reply addressed
    ///      to the new joiner.
    ///   2. `member_added_body` + `member_added_signature` as a
    ///      `MemberAdded` broadcast on the group topic so the existing
    ///      members learn about the late joiner — including their
    ///      Kyber pubkey, which is required for any subsequent rotation
    ///      to deliver to them.
    Accept {
        body: JoinAcceptedBody,
        signature: HybridSignature,
        member_added_body: MemberAddedBody,
        member_added_signature: HybridSignature,
    },
    /// Joiner refused (cap reached, expired, etc.); serialise + publish.
    Reject {
        body: JoinRejectedBody,
        signature: HybridSignature,
    },
    /// The `RequestJoin` referenced an invitation we don't know about.
    /// Treat as silent no-op — likely intended for a different inviter.
    UnknownInvitation,
}

/// Inviter-side handler: validate the joiner's signed `RequestJoin`,
/// look up the matching invitation, run the enrolment, build a signed
/// `JoinAccepted` (or `JoinRejected`) for the caller to publish.
///
/// `gm` must own the inviter's [`GroupManager`] and `inviter_identity`
/// must be the keypair that originally minted the invitation. The
/// function does no I/O — it just transforms state and returns the
/// outcome.
pub fn process_request_join(
    gm: &mut GroupManager,
    inviter_identity: &IdentityKeyPair,
    body: &RequestJoinBody,
    signature: &HybridSignature,
) -> Result<HandshakeOutcome> {
    if !verify_request_join(body, signature)? {
        return Err(anyhow!("RequestJoin signature failed"));
    }

    let invitation = match gm.get_invitation(&body.invitation_code)? {
        Some(i) => i,
        None => return Ok(HandshakeOutcome::UnknownInvitation),
    };
    if invitation.group_id != body.group_id {
        return Err(anyhow!("invitation/group mismatch"));
    }

    let now = now_secs();
    if let Some(exp) = invitation.expires_at {
        if now > exp {
            return Ok(reject(inviter_identity, body, "invitation expired")?);
        }
    }
    if let Some(max) = invitation.max_uses {
        if invitation.current_uses >= max {
            return Ok(reject(inviter_identity, body, "invitation exhausted")?);
        }
    }

    // Enrol the joiner. add_member enforces the 16-member cap.
    if let Err(e) = gm.add_member(
        body.group_id,
        invitation.inviter_id,
        body.joiner_public_key.identity_id,
        body.joiner_public_key.clone(),
        body.joiner_display_name.clone(),
        Role::Member,
    ) {
        let reason = format!("{e}");
        return Ok(reject(inviter_identity, body, &reason)?);
    }
    // Stamp the joiner's long-lived Kyber pubkey on their member
    // record so future key rotations can wrap to them without
    // another handshake. Best-effort: a failure to stamp shouldn't
    // unwind the enrolment, since the join is otherwise complete.
    let _ = gm.set_member_kyber_pub(
        body.group_id,
        body.joiner_public_key.identity_id,
        body.joiner_kyber_pub.clone(),
    );
    let _ = gm.mark_invitation_used(&body.invitation_code);

    // Build the member snapshot + wrap the group key for the joiner.
    // The snapshot now carries each member's Kyber pubkey so the
    // joiner's local view can route subsequent rotations back to
    // existing members.
    let group = gm
        .get_group(&body.group_id)
        .ok_or_else(|| anyhow!("group vanished after add_member"))?;
    let members: Vec<GroupMemberSummary> = group
        .members
        .values()
        .map(|m| GroupMemberSummary {
            identity_id: m.identity_id,
            identity_key: m.identity_key.clone(),
            display_name: m.display_name.clone(),
            role: m.role.clone(),
            joined_at: m.joined_at,
            kyber_pub: m.kyber_pub.clone(),
        })
        .collect();
    let group_name = group.name.clone();
    // Snapshot the inviter's `group.version` *after* `add_member`
    // ran, so the joiner adopts the post-enrolment value. Same
    // counter the generation gates in `decrypt_group_message` and
    // `process_key_rotation` compare against.
    let snapshot_version = group.version;

    // Pull out the new member's snapshot for the broadcast. Cloning
    // out of the borrow keeps the rest of this function from running
    // into split-borrow hassles.
    let new_member_summary = members
        .iter()
        .find(|m| m.identity_id == body.joiner_public_key.identity_id)
        .cloned()
        .ok_or_else(|| anyhow!("new member missing from snapshot"))?;

    gm.ensure_group_key(body.group_id)?;
    let mut group_key = gm
        .export_group_key(&body.group_id)
        .ok_or_else(|| anyhow!("group key missing after ensure"))?;
    let wrapped_group_key = WrappedGroupKey::wrap(&group_key, &body.joiner_kyber_pub)?;
    group_key.zeroize();

    let accepted_body = JoinAcceptedBody {
        group_id: body.group_id,
        invitation_code: body.invitation_code.clone(),
        group_name,
        members,
        joiner_id: body.joiner_public_key.identity_id,
        wrapped_group_key,
        snapshot_version,
    };
    let (accepted_body, accepted_signature) = match sign_join_accepted(
        inviter_identity,
        accepted_body,
    )? {
        crate::groups::group_handshake::GroupHandshake::JoinAccepted { body, signature } => {
            (body, signature)
        }
        _ => unreachable!("sign_join_accepted always returns JoinAccepted"),
    };

    let member_added_payload = MemberAddedBody {
        group_id: body.group_id,
        adder_id: invitation.inviter_id,
        new_member: new_member_summary,
        new_version: snapshot_version,
        timestamp: now,
    };
    let (member_added_body, member_added_signature) = match sign_member_added(
        inviter_identity,
        member_added_payload,
    )? {
        crate::groups::group_handshake::GroupHandshake::MemberAdded { body, signature } => {
            (body, signature)
        }
        _ => unreachable!("sign_member_added always returns MemberAdded"),
    };

    Ok(HandshakeOutcome::Accept {
        body: accepted_body,
        signature: accepted_signature,
        member_added_body,
        member_added_signature,
    })
}

/// Joiner-side handler: verify the inviter's signed `JoinAccepted`,
/// unwrap the KEM-encrypted group key with the joiner's cached Kyber
/// secret, and promote the local invite receipt into a real Group.
///
/// `expected_inviter_id` comes from the joiner's local receipt of the
/// original invite — passing it explicitly keeps this handler
/// independent of where the receipt is stored.
pub fn process_join_accepted(
    gm: &mut GroupManager,
    expected_inviter_id: IdentityId,
    body: &JoinAcceptedBody,
    signature: &HybridSignature,
    joiner_kyber_secret: &[u8],
) -> Result<()> {
    let inviter_key: IdentityKey = body
        .members
        .iter()
        .find(|m| m.identity_id == expected_inviter_id)
        .map(|m| m.identity_key.clone())
        .ok_or_else(|| anyhow!("inviter not in member snapshot"))?;

    if !verify_join_accepted(body, signature, &inviter_key)? {
        return Err(anyhow!("JoinAccepted signature failed"));
    }

    let mut group_key = body
        .wrapped_group_key
        .unwrap(joiner_kyber_secret)
        .context("group key unwrap failed")?;

    let now = now_secs();
    let mut members = HashMap::new();
    for m in &body.members {
        members.insert(
            m.identity_id,
            GroupMember {
                identity_id: m.identity_id,
                identity_key: m.identity_key.clone(),
                display_name: m.display_name.clone(),
                role: m.role.clone(),
                joined_at: m.joined_at,
                last_seen: now,
                invited_by: Some(expected_inviter_id),
                member_status: MemberStatus::Active,
                custom_permissions: None,
                kyber_pub: m.kyber_pub.clone(),
            },
        );
    }

    gm.confirm_external_invite_acceptance(
        body.group_id,
        body.group_name.clone(),
        members,
        &group_key,
        body.snapshot_version,
    )?;
    group_key.zeroize();

    // Promote the joiner's then-ephemeral Kyber secret into long-lived
    // per-group storage so future KeyRotation messages can be unwrapped
    // even after a process restart. Errors here only mean the joiner
    // won't be able to receive rotations — they'd need to rejoin —
    // but the join itself has already landed, so we don't unwind.
    if let Err(e) = gm.store_my_kyber_secret(body.group_id, joiner_kyber_secret) {
        eprintln!("warning: persisting joiner Kyber secret failed: {e:#}");
    }
    Ok(())
}

/// Existing-member handler for inviter-broadcast `MemberAdded`. Verifies
/// the broadcast was signed by an actual current admin/owner of the
/// local group and applies the new member to the local view so future
/// rotations from this device can deliver to them. Idempotent — a
/// repeat broadcast for a member already in the local view is a no-op.
pub fn process_member_added(
    gm: &mut GroupManager,
    body: &MemberAddedBody,
    signature: &HybridSignature,
) -> Result<()> {
    let group = gm
        .get_group(&body.group_id)
        .ok_or_else(|| anyhow!("MemberAdded for unknown group"))?;
    let adder = group
        .members
        .get(&body.adder_id)
        .ok_or_else(|| anyhow!("MemberAdded adder is not a current member"))?;
    if !matches!(adder.role, Role::Owner | Role::Admin) {
        return Err(anyhow!("MemberAdded adder lacks Add permission"));
    }
    if !verify_member_added(body, signature, &adder.identity_key)? {
        return Err(anyhow!("MemberAdded signature failed"));
    }
    if group.members.contains_key(&body.new_member.identity_id) {
        // Already known — late or duplicate broadcast.
        return Ok(());
    }
    let new_member = GroupMember {
        identity_id: body.new_member.identity_id,
        identity_key: body.new_member.identity_key.clone(),
        display_name: body.new_member.display_name.clone(),
        role: body.new_member.role.clone(),
        joined_at: body.new_member.joined_at,
        last_seen: body.new_member.joined_at,
        invited_by: Some(body.adder_id),
        member_status: MemberStatus::Active,
        custom_permissions: None,
        kyber_pub: body.new_member.kyber_pub.clone(),
    };
    gm.apply_member_added(body.group_id, new_member, body.new_version)
}

/// Existing-member handler for owner-broadcast `RoleChange`. Verifies
/// the broadcast was signed by the local view's current owner of the
/// group and applies the role change.
pub fn process_role_change(
    gm: &mut GroupManager,
    body: &RoleChangeBody,
    signature: &HybridSignature,
) -> Result<()> {
    let group = gm
        .get_group(&body.group_id)
        .ok_or_else(|| anyhow!("RoleChange for unknown group"))?;
    let promoter = group
        .members
        .get(&body.promoter_id)
        .ok_or_else(|| anyhow!("RoleChange promoter is not a current member"))?;
    if promoter.role != Role::Owner {
        return Err(anyhow!("RoleChange promoter is not the owner"));
    }
    let promoter_key = promoter.identity_key.clone();
    if !verify_role_change(body, signature, &promoter_key)? {
        return Err(anyhow!("RoleChange signature failed"));
    }
    gm.apply_role_change(
        body.group_id,
        body.member_id,
        body.new_role.clone(),
        body.new_version,
    )
}

/// Responder-side handler for `RequestStateSync`. Confirms the
/// requester is still an active member of the local view, verifies
/// the request signature, and builds a signed `StateSyncResponse`
/// carrying the responder's current snapshot. Returns `Ok(None)` if
/// the local view doesn't contain the group at all (the request was
/// for someone else's group), or if the requester isn't an active
/// member here (don't leak roster to ex-members).
pub fn process_request_state_sync(
    gm: &GroupManager,
    responder_identity: &IdentityKeyPair,
    body: &RequestStateSyncBody,
    signature: &HybridSignature,
) -> Result<Option<(StateSyncResponseBody, HybridSignature)>> {
    let group = match gm.get_group(&body.group_id) {
        Some(g) => g,
        None => return Ok(None),
    };
    let requester = match group.members.get(&body.requester_id) {
        Some(m) => m,
        None => return Ok(None),
    };
    if requester.member_status != MemberStatus::Active {
        return Ok(None);
    }
    if !verify_request_state_sync(body, signature, &requester.identity_key)? {
        return Err(anyhow!("RequestStateSync signature failed"));
    }

    // Refuse to respond if the responder isn't themselves an active
    // member — a former member shouldn't be authoritative about the
    // current roster. The ContactsViewModel-level local state we
    // hold for them is "outdated by design".
    let responder_id = responder_identity.identity_id();
    let responder = match group.members.get(&responder_id) {
        Some(m) if m.member_status == MemberStatus::Active => m,
        _ => return Ok(None),
    };
    let _ = responder; // Used only for the active-membership gate.

    let members: Vec<GroupMemberSummary> = group
        .members
        .values()
        .filter(|m| m.member_status == MemberStatus::Active)
        .map(|m| GroupMemberSummary {
            identity_id: m.identity_id,
            identity_key: m.identity_key.clone(),
            display_name: m.display_name.clone(),
            role: m.role.clone(),
            joined_at: m.joined_at,
            kyber_pub: m.kyber_pub.clone(),
        })
        .collect();
    let response = StateSyncResponseBody {
        group_id: body.group_id,
        responder_id,
        requester_id: body.requester_id,
        members,
        current_version: group.version,
        timestamp: now_secs(),
    };
    let (resp_body, resp_sig) =
        match sign_state_sync_response(responder_identity, response)? {
            crate::groups::group_handshake::GroupHandshake::StateSyncResponse {
                body,
                signature,
            } => (body, signature),
            _ => unreachable!("sign_state_sync_response always returns StateSyncResponse"),
        };
    Ok(Some((resp_body, resp_sig)))
}

/// Requester-side handler for inbound `StateSyncResponse`. Verifies
/// the responder was at one point an active member of the local
/// view (so a stranger can't poison the snapshot), then merges the
/// snapshot into local state via `GroupManager::apply_state_sync`.
///
/// Drops the response silently when the recipient isn't actually
/// the addressed `requester_id` — gossipsub fan-out delivers the
/// reply to everyone on the group topic, so each recipient has to
/// self-filter.
pub fn process_state_sync_response(
    gm: &mut GroupManager,
    self_id: IdentityId,
    body: &StateSyncResponseBody,
    signature: &HybridSignature,
) -> Result<bool> {
    if body.requester_id != self_id {
        return Ok(false);
    }
    let group = gm
        .get_group(&body.group_id)
        .ok_or_else(|| anyhow!("StateSyncResponse for unknown group"))?;
    // The responder may have been promoted / demoted since our local
    // view last updated, but they must still be a current member.
    // Reject snapshots from someone we don't know — that's the same
    // posture as MemberAdded / RoleChange.
    let responder = group
        .members
        .get(&body.responder_id)
        .ok_or_else(|| anyhow!("StateSyncResponse responder is not in local view"))?;
    if responder.member_status != MemberStatus::Active {
        return Err(anyhow!("StateSyncResponse responder is not active"));
    }
    if !verify_state_sync_response(body, signature, &responder.identity_key)? {
        return Err(anyhow!("StateSyncResponse signature failed"));
    }
    gm.apply_state_sync(body.group_id, &body.members, body.current_version)?;
    Ok(true)
}

fn reject(
    identity: &IdentityKeyPair,
    request: &RequestJoinBody,
    reason: &str,
) -> Result<HandshakeOutcome> {
    let body = JoinRejectedBody {
        group_id: request.group_id,
        invitation_code: request.invitation_code.clone(),
        joiner_id: request.joiner_public_key.identity_id,
        reason: reason.to_string(),
    };
    match sign_join_rejected(identity, body)? {
        crate::groups::group_handshake::GroupHandshake::JoinRejected { body, signature } => {
            Ok(HandshakeOutcome::Reject { body, signature })
        }
        _ => unreachable!("sign_join_rejected always returns JoinRejected"),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

/// Plan a key rotation triggered by removing a member (or by a
/// proactive rotation request from the owner).
///
/// Returns a fully signed `KeyRotation` payload + the new in-process
/// group key so the caller can install it locally before publishing.
/// Side effects on `gm`: the member is removed (if `removed_member`
/// is `Some`) and the new key is installed in `group_crypto`.
pub fn plan_key_rotation(
    gm: &mut GroupManager,
    rotator_identity: &IdentityKeyPair,
    group_id: GroupId,
    removed_member: Option<IdentityId>,
    reason: &str,
) -> Result<GroupHandshake> {
    let rotator_id = rotator_identity.identity_id();

    // The rotator must hold RemoveMembers in this group, even for
    // proactive rotations — only roles that could have removed someone
    // get to redistribute the key.
    gm.check_permission(group_id, rotator_id, Permission::RemoveMembers)
        .context("rotator lacks RemoveMembers permission")?;

    if let Some(target) = removed_member {
        gm.remove_member(group_id, rotator_id, target, reason.to_string())
            .context("remove_member during rotation")?;
    }

    let recipients = gm.rotate_group_key_after_removal(group_id, rotator_id)?;
    // Read the freshly installed key so we can wrap it for each
    // remaining member that has a registered Kyber pubkey.
    let new_key = gm
        .export_group_key(&group_id)
        .ok_or_else(|| anyhow!("group key vanished after rotation"))?;
    let mut deliveries: Vec<MemberKeyDelivery> = Vec::with_capacity(recipients.len());
    for (recipient_id, kyber_pub) in recipients {
        let wrapped = WrappedGroupKey::wrap(&new_key, &kyber_pub)
            .context("wrap new group key for recipient")?;
        deliveries.push(MemberKeyDelivery {
            recipient_id,
            wrapped_key: wrapped,
        });
    }

    let body = KeyRotationBody {
        group_id,
        // Use the group's `version` as the monotonic generation —
        // remove_member already bumped it, so this counter only ever
        // moves forward without us having to keep separate state.
        generation: gm
            .get_group(&group_id)
            .map(|g| g.version)
            .unwrap_or(0),
        rotator_id,
        removed_member_id: removed_member,
        deliveries,
        timestamp: now_secs(),
    };

    sign_key_rotation(rotator_identity, body)
}

/// Joiner-side handler for a `KeyRotation` frame broadcast on the
/// group's per-group topic. Verifies that the rotator is actually a
/// member with `RemoveMembers` permission, finds our own delivery
/// (if any), unwraps the new group key with our long-lived per-group
/// Kyber secret, and installs it.
///
/// `local_id` is the IdentityId of the device running this handler
/// (so we can pick our own delivery out of the broadcast).
pub fn process_key_rotation(
    gm: &mut GroupManager,
    local_id: IdentityId,
    body: &KeyRotationBody,
    signature: &HybridSignature,
) -> Result<()> {
    // Find the rotator in our local membership and verify they're an
    // active member who's allowed to rotate. Trust comes from "the
    // signed body's rotator_id matches a member we already trust".
    let group = gm
        .get_group(&body.group_id)
        .ok_or_else(|| anyhow!("KeyRotation for unknown group"))?;

    // Generation gate (symmetric to `decrypt_group_message`): drop
    // rotations whose generation isn't strictly newer than our
    // current view. Stale rotations (old generation) are no-ops we'd
    // otherwise apply on top of a newer key; equal-generation
    // rotations would reset us to the same key version we're already
    // on. Both are safety bugs in waiting.
    if body.generation <= group.version {
        return Err(anyhow!(
            "KeyRotation generation not newer than local (frame={}, local={})",
            body.generation,
            group.version
        ));
    }

    let rotator = group
        .members
        .get(&body.rotator_id)
        .ok_or_else(|| anyhow!("KeyRotation from non-member"))?;
    if rotator.member_status != MemberStatus::Active {
        return Err(anyhow!("KeyRotation from inactive member"));
    }
    let rotator_key = rotator.identity_key.clone();

    if !verify_key_rotation(body, signature, &rotator_key)? {
        return Err(anyhow!("KeyRotation signature failed"));
    }

    // Permission gate: the rotator must hold RemoveMembers in our
    // local view of the group.
    gm.check_permission(body.group_id, body.rotator_id, Permission::RemoveMembers)
        .context("rotator lacks RemoveMembers in local view")?;

    // Apply the rotator's own bookkeeping: remove the named member
    // from our local copy of the group, if any.
    if let Some(removed) = body.removed_member_id {
        if removed != local_id {
            // We're not the one being kicked — sync our membership.
            let _ = gm.remove_member(body.group_id, body.rotator_id, removed, "rotation".to_string());
        } else {
            // The KeyRotation announces our own removal. Do nothing
            // with the wrapped keys (they wouldn't be addressed to
            // us anyway). Wipe our long-lived Kyber secret so the
            // kicked-out copy can't decapsulate any future rotations.
            let _ = gm.wipe_my_kyber_secret(body.group_id);
            return Ok(());
        }
    }

    // Find our delivery, unwrap, and install.
    let our_delivery = body
        .deliveries
        .iter()
        .find(|d| d.recipient_id == local_id)
        .ok_or_else(|| anyhow!("no rotation delivery addressed to us"))?;

    let secret = gm
        .load_my_kyber_secret(body.group_id)?
        .ok_or_else(|| anyhow!("no persisted Kyber secret for group"))?;
    let mut new_key = our_delivery
        .wrapped_key
        .unwrap(&secret)
        .context("unwrap rotated group key")?;
    drop(secret);

    gm.install_group_key(body.group_id, &new_key)?;
    new_key.zeroize();
    Ok(())
}
