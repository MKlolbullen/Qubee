use anyhow::{Result};
use pqcrypto_dilithium::dilithium2;
use secrecy::{Secret, ExposeSecret};
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub sk: Secret<Vec<u8>>,
    pub pk: Vec<u8>,
}

impl IdentityKeyPair {
    pub fn generate() -> Result<Self> {
        let (sk, pk) = dilithium2::keypair();
        Ok(Self {
            sk: Secret::new(sk.0.to_vec()),
            pk: pk.0.to_vec(),
        })
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium2::SecretKey::from_bytes(self.sk.expose_secret())?;
        let signature = dilithium2::sign(message, &sk);
        Ok(signature.0.to_vec())
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let pk = dilithium2::PublicKey::from_bytes(&self.pk)?;
        let sig = dilithium2::Signature::from_bytes(signature)?;
        dilithium2::verify(message, &sig, &pk)
            .map_err(|_| anyhow::anyhow!("Signature verification failed"))
    }
}
