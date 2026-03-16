use anyhow::{Context, Result};
use zeroize::Zeroizing;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};
use hkdf::Hkdf;
use sha2::Sha256;

pub const PQ_REKEY_PERIOD: u32 = 50;

/// Minimal symmetric ratchet used by the legacy messaging path (pre-native_contract).
/// Replaces the incompatible double_ratchet 0.1.0 API while preserving the call interface
/// expected by secure_message.rs, audio.rs, and file_transfer.rs.
#[derive(Clone)]
pub struct SymmetricRatchet {
    chain_key: [u8; 32],
    send_counter: u32,
    recv_counter: u32,
}

impl SymmetricRatchet {
    pub fn new(_initiator: bool) -> Self {
        SymmetricRatchet {
            chain_key: [0u8; 32],
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Advance the send chain; returns (header_bytes, message_key_length).
    pub fn send(&mut self, _msg_len: u32) -> (Vec<u8>, usize) {
        let (ck, _mk) = self.advance_chain();
        self.chain_key = ck;
        let header = self.send_counter.to_le_bytes().to_vec();
        self.send_counter += 1;
        (header, 32)
    }

    /// Advance the receive chain using the supplied header.
    pub fn recv(&mut self, _header: &[u8]) -> Result<()> {
        let (ck, _mk) = self.advance_chain();
        self.chain_key = ck;
        self.recv_counter += 1;
        Ok(())
    }

    /// Return the current chain key as the root key for HKDF mixing.
    pub fn root_key(&self) -> &[u8] {
        &self.chain_key
    }

    fn advance_chain(&self) -> ([u8; 32], [u8; 32]) {
        let hkdf = Hkdf::<Sha256>::new(None, &self.chain_key);
        let mut ck = [0u8; 32];
        let mut mk = [0u8; 32];
        hkdf.expand(b"chain_key", &mut ck).expect("hkdf expand ck");
        hkdf.expand(b"message_key", &mut mk).expect("hkdf expand mk");
        (ck, mk)
    }
}

#[derive(Clone)]
pub struct HybridRatchet {
    pub dr: SymmetricRatchet,
    pub pq_pk: kyber768::PublicKey,
    pub pq_sk: kyber768::SecretKey,
    pq_shared: Zeroizing<Vec<u8>>,
    pub send_ctr: u32,
}

impl HybridRatchet {
    pub fn new(initiator: bool) -> Result<Self> {
        let dr = SymmetricRatchet::new(initiator);
        let (pq_pk, pq_sk) = kyber768::keypair();
        Ok(Self {
            dr,
            pq_pk,
            pq_sk,
            pq_shared: Zeroizing::new(vec![0u8; 32]),
            send_ctr: 0,
        })
    }

    pub fn pq_reencap(&mut self, remote_pk: &kyber768::PublicKey) -> Result<Vec<u8>> {
        let (ss, ct) = kyber768::encapsulate(remote_pk);
        self.pq_shared = Zeroizing::new(ss.as_bytes().to_vec());
        Ok(ct.as_bytes().to_vec())
    }

    pub fn pq_decaps(&mut self, ct_bytes: &[u8]) -> Result<()> {
        let ct = kyber768::Ciphertext::from_bytes(ct_bytes).context("bad Kyber ciphertext")?;
        let ss = kyber768::decapsulate(&ct, &self.pq_sk);
        self.pq_shared = Zeroizing::new(ss.as_bytes().to_vec());
        Ok(())
    }

    pub fn derive_root_key(&self) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(&self.pq_shared), self.dr.root_key());
        let mut key = [0u8; 32];
        hk.expand(b"hybrid_root", &mut key).expect("hkdf expand");
        Zeroizing::new(key)
    }
}
