//! Hybrid-signed onboarding bundle for new Qubee identities.
//!
//! When a user installs Qubee they generate a hybrid identity keypair
//! (Ed25519 + Dilithium-2). The resulting [`OnboardingBundle`] carries
//! their public key plus a *real* [`HybridSignature`] over the bundle's
//! canonical bytes — both signature halves must verify, which means
//! anyone replaying or tampering with a `qubee://identity/<token>` link
//! is rejected at decode time.
//!
//! There is no zero-knowledge proof here: Qubee's onboarding QR is a
//! presentation of an *existing* public identity, not a private input
//! we want to hide. A signature with a freshness timestamp is the
//! right primitive for that, and we already have one.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::identity::identity_key::{
    HybridSignature, IdentityId, IdentityKey, IdentityKeyPair,
};
use crate::sessions::handshake::DmPreKeyBundle;

pub const QUBEE_IDENTITY_HOST: &str = "identity";
/// Domain separator for the bytes the bundle's signature covers.
/// Bumped to `v3` when the optional `dm_prekey_bundle` field was
/// added; `v2` bundles still verify against the v2 tag (different
/// canonical bytes) so older clients fail gracefully on encounter.
pub const ONBOARDING_DOMAIN_TAG: &[u8] = b"qubee_onboarding_v3";
/// Maximum age of an onboarding bundle, in seconds. Older bundles are
/// rejected at decode time so a leaked QR can't follow you forever.
pub const ONBOARDING_BUNDLE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Public-facing onboarding bundle. Signed by the identity it advertises.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnboardingBundle {
    pub display_name: String,
    pub user_id: String,
    pub public_key: IdentityKey,
    /// Optional DM prekey bundle so receivers can establish a
    /// forward-secret + post-quantum-secure DM session
    /// immediately after accepting the contact, without a
    /// separate prekey-exchange round-trip. None for backward-
    /// compatible "identity-only" bundles; v3 bundles produced by
    /// `create` always include one.
    #[serde(default)]
    pub dm_prekey_bundle: Option<Vec<u8>>,
    /// Hybrid signature over the canonical bytes of `(display_name,
    /// user_id, public_key, dm_prekey_bundle)` plus a
    /// domain-separation tag.
    pub signature: HybridSignature,
}

impl OnboardingBundle {
    /// Generate a freshly signed bundle from a freshly created keypair.
    /// The keypair is borrowed (not consumed) so the caller can also
    /// persist it to the secure keystore for reload on next launch.
    ///
    /// `dm_prekey_bundle_bytes`, when `Some`, is a serialized
    /// [`DmPreKeyBundle`] (i.e. the output of
    /// [`DmPreKeyBundle::to_wire`]) the embedder produced via the
    /// JNI bridge. It rides inside the signed envelope so the
    /// receiver can verify it came from the same identity that
    /// signed the bundle.
    pub fn create(
        keypair: &IdentityKeyPair,
        display_name: impl Into<String>,
        user_id: impl Into<String>,
        dm_prekey_bundle_bytes: Option<Vec<u8>>,
    ) -> Result<Self> {
        let display_name = display_name.into();
        let user_id = user_id.into();
        let public_key = keypair.public_key();
        let payload = canonical_payload(
            &display_name,
            &user_id,
            &public_key,
            dm_prekey_bundle_bytes.as_deref(),
        )?;
        let signature = keypair.sign(&payload).context("onboarding sign failed")?;
        Ok(OnboardingBundle {
            display_name,
            user_id,
            public_key,
            dm_prekey_bundle: dm_prekey_bundle_bytes,
            signature,
        })
    }

    /// Encode the bundle as a `qubee://identity/<base64url>` deep link.
    pub fn to_share_link(&self) -> Result<String> {
        let bytes = bincode::serialize(self).context("onboarding serialize failed")?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        Ok(format!("qubee://{}/{}", QUBEE_IDENTITY_HOST, token))
    }

    /// Parse and cryptographically verify a previously generated share link.
    pub fn from_share_link(link: &str) -> Result<Self> {
        let prefix = format!("qubee://{}/", QUBEE_IDENTITY_HOST);
        let token = link
            .strip_prefix(&prefix)
            .ok_or_else(|| anyhow!("not a qubee identity link"))?;
        let token = token.split(['?', '#']).next().unwrap_or(token);
        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .context("identity token is not valid base64url")?;
        let bundle: OnboardingBundle =
            bincode::deserialize(&bytes).context("identity payload could not be decoded")?;
        bundle.verify()?;
        Ok(bundle)
    }

    /// Verify both signature halves and that the bundle isn't older
    /// than [`ONBOARDING_BUNDLE_TTL_SECS`]. Also validates that the
    /// embedded DM prekey bundle (when present) carries the same
    /// signer identity as the outer bundle — defends against a
    /// peer swapping in someone else's prekey bundle.
    pub fn verify(&self) -> Result<()> {
        let payload = canonical_payload(
            &self.display_name,
            &self.user_id,
            &self.public_key,
            self.dm_prekey_bundle.as_deref(),
        )?;
        match self
            .public_key
            .verify_with_max_age(&payload, &self.signature, ONBOARDING_BUNDLE_TTL_SECS)
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(anyhow!(
                    "onboarding bundle is invalid (bad signature, wrong signer, or expired)"
                ))
            }
            Err(e) => return Err(anyhow!("onboarding signature could not be verified: {e}")),
        }

        if let Some(bytes) = &self.dm_prekey_bundle {
            let dm = DmPreKeyBundle::from_wire(bytes).context(
                "embedded DM prekey bundle could not be decoded",
            )?;
            if dm.identity.identity_id != self.public_key.identity_id {
                return Err(anyhow!(
                    "embedded DM prekey bundle's identity doesn't match the outer onboarding identity"
                ));
            }
        }

        Ok(())
    }

    pub fn identity_id(&self) -> IdentityId {
        self.public_key.identity_id
    }
}

fn canonical_payload(
    display_name: &str,
    user_id: &str,
    public_key: &IdentityKey,
    dm_prekey_bundle: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut out =
        Vec::with_capacity(64 + display_name.len() + user_id.len() + dm_prekey_bundle.map_or(0, |b| b.len()));
    out.extend_from_slice(ONBOARDING_DOMAIN_TAG);
    out.push(0u8);
    out.extend_from_slice(display_name.as_bytes());
    out.push(0u8);
    out.extend_from_slice(user_id.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&bincode::serialize(public_key).context("pubkey serialize")?);
    out.push(0u8);
    // Length-prefix the optional DM prekey bundle so a missing
    // vs an empty bundle produces distinct canonical bytes.
    match dm_prekey_bundle {
        Some(b) => {
            out.push(1u8);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
        None => {
            out.push(0u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_share_link() {
        let kp = IdentityKeyPair::generate().unwrap();
        let bundle = OnboardingBundle::create(&kp, "Alice", "uid-1", None).unwrap();
        let link = bundle.to_share_link().unwrap();
        assert!(link.starts_with("qubee://identity/"));
        let back = OnboardingBundle::from_share_link(&link).unwrap();
        assert_eq!(back.display_name, "Alice");
        assert_eq!(back.user_id, "uid-1");
        assert_eq!(back.identity_id(), bundle.identity_id());
        assert!(back.dm_prekey_bundle.is_none());
    }

    #[test]
    fn roundtrip_with_dm_prekey_bundle() {
        use crate::sessions::handshake::generate_prekey_bundle;
        let kp = IdentityKeyPair::generate().unwrap();
        let (dm_bundle, _secrets) = generate_prekey_bundle(&kp, 1).unwrap();
        let dm_bytes = dm_bundle.to_wire().unwrap();
        let bundle =
            OnboardingBundle::create(&kp, "Alice", "uid-1", Some(dm_bytes.clone())).unwrap();
        let link = bundle.to_share_link().unwrap();
        let back = OnboardingBundle::from_share_link(&link).unwrap();
        assert_eq!(back.dm_prekey_bundle.as_ref().unwrap(), &dm_bytes);
    }

    #[test]
    fn rejects_swapped_signer() {
        let kp1 = IdentityKeyPair::generate().unwrap();
        let kp2 = IdentityKeyPair::generate().unwrap();
        let mut bundle = OnboardingBundle::create(&kp1, "Alice", "uid-1", None).unwrap();
        bundle.public_key = kp2.public_key();
        let link = bundle.to_share_link().unwrap();
        assert!(OnboardingBundle::from_share_link(&link).is_err());
    }

    #[test]
    fn rejects_dm_bundle_with_mismatched_identity() {
        // Outer bundle is signed by kp1 but the embedded DM
        // prekey bundle was produced by kp2. The outer signature
        // is still valid (the bytes match what kp1 signed) — but
        // `verify` should refuse the cross-signer mismatch.
        use crate::sessions::handshake::generate_prekey_bundle;
        let kp1 = IdentityKeyPair::generate().unwrap();
        let kp2 = IdentityKeyPair::generate().unwrap();
        let (rogue_dm, _secrets) = generate_prekey_bundle(&kp2, 1).unwrap();
        let bundle = OnboardingBundle::create(
            &kp1,
            "Alice",
            "uid-1",
            Some(rogue_dm.to_wire().unwrap()),
        )
        .unwrap();
        let link = bundle.to_share_link().unwrap();
        assert!(OnboardingBundle::from_share_link(&link).is_err());
    }
}
