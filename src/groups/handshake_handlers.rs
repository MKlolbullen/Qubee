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
    sign_join_accepted, sign_join_rejected, verify_join_accepted, verify_request_join,
    GroupMemberSummary, JoinAcceptedBody, JoinRejectedBody, RequestJoinBody, WrappedGroupKey,
};
use crate::groups::group_manager::{GroupManager, GroupMember, MemberStatus};
use crate::groups::group_permissions::Role;
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
