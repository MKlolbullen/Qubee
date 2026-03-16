use anyhow::Result;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub sk: Zeroizing<Vec<u8>>,
    pub pk: Vec<u8>,
}

impl IdentityKeyPair {
    pub fn generate() -> Result<Self> {
        // keypair() returns (PublicKey, SecretKey)
        let (pk, sk) = dilithium2::keypair();
        Ok(Self {
            sk: Zeroizing::new(sk.as_bytes().to_vec()),
            pk: pk.as_bytes().to_vec(),
        })
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium2::SecretKey::from_bytes(&self.sk)?;
        let signature = dilithium2::detached_sign(message, &sk);
        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let pk = dilithium2::PublicKey::from_bytes(&self.pk)?;
        let sig = dilithium2::DetachedSignature::from_bytes(signature)?;
        dilithium2::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }
}
