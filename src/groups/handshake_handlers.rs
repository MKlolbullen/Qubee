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
    sign_join_accepted, sign_join_rejected, sign_key_rotation, verify_join_accepted,
    verify_key_rotation, verify_request_join, GroupHandshake, GroupMemberSummary,
    JoinAcceptedBody, JoinRejectedBody, KeyRotationBody, MemberKeyDelivery, RequestJoinBody,
    WrappedGroupKey,
};
use crate::groups::group_manager::{GroupId, GroupManager, GroupMember, MemberStatus};
use crate::groups::group_permissions::{Permission, Role};
use crate::identity::identity_key::{HybridSignature, IdentityId, IdentityKey, IdentityKeyPair};

/// What the inviter wants to publish back after handling a `RequestJoin`.
#[derive(Debug)]
pub enum HandshakeOutcome {
    /// Joiner enrolled successfully; serialise + publish this body.
    Accept {
        body: JoinAcceptedBody,
        signature: HybridSignature,
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
        })
        .collect();
    let group_name = group.name.clone();

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
    };
    let signed = match sign_join_accepted(inviter_identity, accepted_body)? {
        crate::groups::group_handshake::GroupHandshake::JoinAccepted { body, signature } => {
            HandshakeOutcome::Accept { body, signature }
        }
        _ => unreachable!("sign_join_accepted always returns JoinAccepted"),
    };
    Ok(signed)
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
                // Snapshot from the wire doesn't carry per-member
                // Kyber pubkeys today — the joiner only learns the
                // inviter's metadata and the member list. Future
                // KeyRotation deliveries to legacy members get
                // skipped because of the empty-vec gate in
                // rotate_group_key_after_removal.
                kyber_pub: Vec::new(),
            },
        );
    }

    gm.confirm_external_invite_acceptance(
        body.group_id,
        body.group_name.clone(),
        members,
        &group_key,
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
