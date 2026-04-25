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

pub const QUBEE_IDENTITY_HOST: &str = "identity";
/// Domain separator for the bytes the bundle's signature covers.
pub const ONBOARDING_DOMAIN_TAG: &[u8] = b"qubee_onboarding_v2";
/// Maximum age of an onboarding bundle, in seconds. Older bundles are
/// rejected at decode time so a leaked QR can't follow you forever.
pub const ONBOARDING_BUNDLE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Public-facing onboarding bundle. Signed by the identity it advertises.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnboardingBundle {
    pub display_name: String,
    pub user_id: String,
    pub public_key: IdentityKey,
    /// Hybrid signature over the canonical bytes of `(display_name,
    /// user_id, public_key)` plus a domain-separation tag.
    pub signature: HybridSignature,
}

impl OnboardingBundle {
    /// Generate a freshly signed bundle from a freshly created keypair.
    /// The keypair is borrowed (not consumed) so the caller can also
    /// persist it to the secure keystore for reload on next launch.
    pub fn create(
        keypair: &IdentityKeyPair,
        display_name: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Result<Self> {
        let display_name = display_name.into();
        let user_id = user_id.into();
        let public_key = keypair.public_key();
        let payload = canonical_payload(&display_name, &user_id, &public_key)?;
        let signature = keypair.sign(&payload).context("onboarding sign failed")?;
        Ok(OnboardingBundle {
            display_name,
            user_id,
            public_key,
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
    /// than [`ONBOARDING_BUNDLE_TTL_SECS`].
    pub fn verify(&self) -> Result<()> {
        let payload = canonical_payload(&self.display_name, &self.user_id, &self.public_key)?;
        match self
            .public_key
            .verify_with_max_age(&payload, &self.signature, ONBOARDING_BUNDLE_TTL_SECS)
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(anyhow!(
                "onboarding bundle is invalid (bad signature, wrong signer, or expired)"
            )),
            Err(e) => Err(anyhow!("onboarding signature could not be verified: {e}")),
        }
    }

    pub fn identity_id(&self) -> IdentityId {
        self.public_key.identity_id
    }
}

fn canonical_payload(
    display_name: &str,
    user_id: &str,
    public_key: &IdentityKey,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64 + display_name.len() + user_id.len());
    out.extend_from_slice(ONBOARDING_DOMAIN_TAG);
    out.push(0u8);
    out.extend_from_slice(display_name.as_bytes());
    out.push(0u8);
    out.extend_from_slice(user_id.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&bincode::serialize(public_key).context("pubkey serialize")?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_share_link() {
        let kp = IdentityKeyPair::generate().unwrap();
        let bundle = OnboardingBundle::create(&kp, "Alice", "uid-1").unwrap();
        let link = bundle.to_share_link().unwrap();
        assert!(link.starts_with("qubee://identity/"));
        let back = OnboardingBundle::from_share_link(&link).unwrap();
        assert_eq!(back.display_name, "Alice");
        assert_eq!(back.user_id, "uid-1");
        assert_eq!(back.identity_id(), bundle.identity_id());
    }

    #[test]
    fn rejects_swapped_signer() {
        let kp1 = IdentityKeyPair::generate().unwrap();
        let kp2 = IdentityKeyPair::generate().unwrap();
        let mut bundle = OnboardingBundle::create(&kp1, "Alice", "uid-1").unwrap();
        bundle.public_key = kp2.public_key();
        let link = bundle.to_share_link().unwrap();
        assert!(OnboardingBundle::from_share_link(&link).is_err());
    }
}
