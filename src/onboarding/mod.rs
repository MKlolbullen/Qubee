//! ZK-backed onboarding for new Qubee identities.
//!
//! When a user first installs Qubee they generate a hybrid identity
//! key pair (Ed25519 + Dilithium-2) and produce a non-interactive
//! Schnorr/Fiat–Shamir-style proof that they actually hold the matching
//! private keys. The resulting [`OnboardingBundle`] can be:
//!
//! * persisted locally (so the device remembers its identity), and
//! * exported as a `qubee://identity/<base64url>` deep link or QR code
//!   for sharing with peers and adding contacts without ever revealing
//!   the private key material.
//!
//! The verifier side (importing a peer's identity from a QR code)
//! checks the embedded ZK proof before trusting the public key.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::identity::identity_key::{IdentityId, IdentityKey, IdentityKeyPair};
use crate::identity::zk_proof::{
    ProofContext, ProofVerificationResult, ZKProof, ZKProofGenerator, ZKProofVerifier,
};

pub const QUBEE_IDENTITY_HOST: &str = "identity";
pub const ONBOARDING_PROOF_PURPOSE: &str = "qubee_onboarding_v1";
/// How long an exported onboarding QR/proof is considered fresh, in seconds.
pub const ONBOARDING_PROOF_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Public-facing onboarding bundle that proves ownership of a hybrid
/// identity key without revealing the private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnboardingBundle {
    /// Friendly display name chosen during onboarding.
    pub display_name: String,
    /// Application-generated stable user id (e.g. UUID).
    pub user_id: String,
    /// Public hybrid identity key.
    pub public_key: IdentityKey,
    /// Zero-knowledge proof of private-key ownership.
    pub proof: ZKProof,
}

impl OnboardingBundle {
    /// Generate a fresh onboarding bundle from a freshly created
    /// `IdentityKeyPair`. The keypair is consumed to highlight that the
    /// caller is responsible for persisting the matching private material
    /// in the secure keystore.
    pub fn create(
        keypair: IdentityKeyPair,
        display_name: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Result<Self> {
        let display_name = display_name.into();
        let user_id = user_id.into();
        let public_key = keypair.public_key();

        let context = ProofContext {
            purpose: ONBOARDING_PROOF_PURPOSE.to_string(),
            audience: None,
            validity_duration: ONBOARDING_PROOF_TTL_SECS,
            additional_data: build_proof_aad(&display_name, &user_id, &public_key.identity_id),
        };

        let generator = ZKProofGenerator::new(keypair);
        let proof = generator.generate_proof(&context)?;

        Ok(OnboardingBundle {
            display_name,
            user_id,
            public_key,
            proof,
        })
    }

    /// Encode the bundle as a `qubee://identity/<base64url>` deep link.
    /// Handy as both an in-band invite ("send me this link") and a QR
    /// code payload.
    pub fn to_share_link(&self) -> Result<String> {
        let bytes = bincode::serialize(self).context("onboarding serialize failed")?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        Ok(format!("qubee://{}/{}", QUBEE_IDENTITY_HOST, token))
    }

    /// Parse and cryptographically verify a previously generated share
    /// link. Returns the bundle on success, or an error describing why
    /// the link could not be trusted.
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

    /// Check that the embedded ZK proof matches the embedded public key.
    pub fn verify(&self) -> Result<()> {
        let context = ProofContext {
            purpose: ONBOARDING_PROOF_PURPOSE.to_string(),
            audience: None,
            validity_duration: ONBOARDING_PROOF_TTL_SECS,
            additional_data: build_proof_aad(
                &self.display_name,
                &self.user_id,
                &self.public_key.identity_id,
            ),
        };
        let verifier = ZKProofVerifier::new();
        match verifier.verify_proof(&self.proof, &self.public_key, &context)? {
            ProofVerificationResult::Valid => Ok(()),
            ProofVerificationResult::Expired => {
                Err(anyhow!("onboarding proof has expired; please re-export"))
            }
            ProofVerificationResult::ReplayAttack => {
                Err(anyhow!("onboarding proof rejected: replay detected"))
            }
            ProofVerificationResult::InvalidContext => {
                Err(anyhow!("onboarding proof has wrong context"))
            }
            ProofVerificationResult::Invalid => Err(anyhow!("onboarding proof is invalid")),
        }
    }

    /// Convenience accessor for the identity's stable hash.
    pub fn identity_id(&self) -> IdentityId {
        self.public_key.identity_id
    }
}

fn build_proof_aad(display_name: &str, user_id: &str, identity_id: &IdentityId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(display_name.len() + user_id.len() + 32);
    aad.extend_from_slice(display_name.as_bytes());
    aad.push(0u8);
    aad.extend_from_slice(user_id.as_bytes());
    aad.push(0u8);
    aad.extend_from_slice(identity_id.as_ref());
    aad
}
