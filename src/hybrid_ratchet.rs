use anyhow::{Context, Result};
use secrecy::{ExposeSecret, Secret};
use pqcrypto_kyber::kyber768;
use chacha20poly1305::Key;
use hkdf::Hkdf;
use sha2::Sha256;
use crate::secure_message;
use crate::file_transfer;
use crate::audio;

pub const PQ_REKEY_PERIOD: u32 = 1;

#[derive(Clone)]
pub struct HybridRatchet {
    pub dr: double_ratchet::Ratchet,
    pub pq_pk: kyber768::PublicKey,
    pub pq_sk: kyber768::SecretKey,
    pq_shared: Secret<Vec<u8>>,
    pub send_ctr: u32,
}

impl HybridRatchet {
    pub fn new(initiator: bool) -> Result<Self> {
        let opts = double_ratchet::RatchetInitOpts::default().enable_half_symmetric_skip();
        let dr = double_ratchet::Ratchet::new(opts, initiator);
        let (pq_sk, pq_pk) = kyber768::keypair();
        Ok(Self {
            dr,
            pq_pk,
            pq_sk,
            pq_shared: Secret::from(vec![0u8; 32]),
            send_ctr: 0,
        })
    }

    pub fn pq_reencap(&mut self, remote_pk: &kyber768::PublicKey) -> Result<Vec<u8>> {
        let (ct, ss) = kyber768::encapsulate(remote_pk);
        self.pq_shared = Secret::from(ss.0.to_vec());
        Ok(ct.0.to_vec())
    }

    pub fn pq_decaps(&mut self, ct_bytes: &[u8]) -> Result<()> {
        let ct = kyber768::Ciphertext::from_bytes(ct_bytes).context("bad Kyber ciphertext")?;
        let ss = kyber768::decapsulate(&ct, &self.pq_sk);
        self.pq_shared = Secret::from(ss.0.to_vec());
        Ok(())
    }

    pub fn derive_root_key(&self) -> Secret<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(self.pq_shared.expose_secret()), self.dr.root_key());
        let mut key = [0u8; 32];
        hk.expand(b"hybrid_root", &mut key).expect("hkdf expand");
        Secret::new(key)
    }
}
