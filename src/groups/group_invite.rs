use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::groups::group_manager::{GroupId, GroupInvitation, QUBEE_MAX_GROUP_MEMBERS};
use crate::identity::identity_key::IdentityId;

/// Scheme used for Qubee deep-links. Both invite links and shared identity
/// payloads ride on this scheme so the Android app can register a single
/// intent filter.
pub const QUBEE_URI_SCHEME: &str = "qubee";

/// Host used for invite links: `qubee://invite/<token>`.
pub const QUBEE_INVITE_HOST: &str = "invite";

/// Compact, signed-ish payload that can be embedded in an invite link or
/// rendered as a QR code. The `fingerprint` is a short BLAKE3 tag over the
/// other fields, primarily for tamper detection of the link itself — the
/// real authentication still happens when the joiner connects to the
/// inviter's peer and exchanges identity keys.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitePayload {
    pub group_id: GroupId,
    pub group_name: String,
    pub inviter_id: IdentityId,
    pub inviter_name: String,
    pub invitation_code: String,
    pub expires_at: Option<u64>,
    pub max_members: usize,
    pub fingerprint: [u8; 8],
}

impl InvitePayload {
    /// Build an invite payload from a `GroupInvitation` issued by the
    /// `GroupManager`. The encoded `max_members` is clamped to the global
    /// Qubee cap so that a malicious or buggy peer cannot signal a higher
    /// limit downstream.
    pub fn from_invitation(inv: &GroupInvitation) -> Self {
        let mut payload = InvitePayload {
            group_id: inv.group_id,
            group_name: inv.group_name.clone(),
            inviter_id: inv.inviter_id,
            inviter_name: inv.inviter_name.clone(),
            invitation_code: inv.invitation_code.clone(),
            expires_at: inv.expires_at,
            max_members: QUBEE_MAX_GROUP_MEMBERS,
            fingerprint: [0u8; 8],
        };
        payload.fingerprint = payload.compute_fingerprint();
        payload
    }

    /// Serialise the payload, then encode it as a URL-safe deep link:
    /// `qubee://invite/<base64url>`.
    pub fn to_invite_link(&self) -> Result<String> {
        let bytes = bincode::serialize(self).context("invite serialize failed")?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        Ok(format!("{}://{}/{}", QUBEE_URI_SCHEME, QUBEE_INVITE_HOST, token))
    }

    /// Parse a `qubee://invite/<token>` deep link and verify its
    /// fingerprint. Returns the embedded payload on success.
    pub fn from_invite_link(link: &str) -> Result<Self> {
        let prefix = format!("{}://{}/", QUBEE_URI_SCHEME, QUBEE_INVITE_HOST);
        let token = link
            .strip_prefix(&prefix)
            .ok_or_else(|| anyhow!("not a qubee invite link"))?;
        // Tolerate optional trailing `?foo=bar` (deep-link routing tags).
        let token = token.split(['?', '#']).next().unwrap_or(token);
        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .context("invite token is not valid base64url")?;
        let payload: InvitePayload =
            bincode::deserialize(&bytes).context("invite payload could not be decoded")?;
        if payload.fingerprint != payload.compute_fingerprint() {
            return Err(anyhow!("invite link fingerprint mismatch (corrupt link?)"));
        }
        if payload.max_members > QUBEE_MAX_GROUP_MEMBERS {
            return Err(anyhow!(
                "invite advertises {} members but Qubee cap is {}",
                payload.max_members,
                QUBEE_MAX_GROUP_MEMBERS
            ));
        }
        Ok(payload)
    }

    fn compute_fingerprint(&self) -> [u8; 8] {
        let mut hasher = Hasher::new();
        hasher.update(b"qubee_invite_v1");
        hasher.update(self.group_id.as_ref());
        hasher.update(self.group_name.as_bytes());
        hasher.update(self.inviter_id.as_ref());
        hasher.update(self.inviter_name.as_bytes());
        hasher.update(self.invitation_code.as_bytes());
        if let Some(exp) = self.expires_at {
            hasher.update(&exp.to_le_bytes());
        }
        hasher.update(&(self.max_members as u32).to_le_bytes());
        let h = hasher.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&h.as_bytes()[..8]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_invitation() -> GroupInvitation {
        GroupInvitation {
            group_id: GroupId::from_bytes([7u8; 32]),
            group_name: "Test Group".to_string(),
            inviter_id: IdentityId::from([3u8; 32]),
            inviter_name: "Alice".to_string(),
            invitation_code: "abc123".to_string(),
            expires_at: Some(1_700_000_000),
            max_uses: Some(5),
            current_uses: 0,
            created_at: 1_699_999_000,
        }
    }

    #[test]
    fn roundtrip_invite_link() {
        let payload = InvitePayload::from_invitation(&dummy_invitation());
        let link = payload.to_invite_link().unwrap();
        assert!(link.starts_with("qubee://invite/"));
        let back = InvitePayload::from_invite_link(&link).unwrap();
        assert_eq!(payload, back);
    }

    #[test]
    fn rejects_tampered_link() {
        let payload = InvitePayload::from_invitation(&dummy_invitation());
        let link = payload.to_invite_link().unwrap();
        // Flip a character in the token portion — fingerprint must reject it.
        let mut chars: Vec<char> = link.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(InvitePayload::from_invite_link(&tampered).is_err());
    }

    #[test]
    fn rejects_non_qubee_scheme() {
        assert!(InvitePayload::from_invite_link("https://example.com/foo").is_err());
    }
}
