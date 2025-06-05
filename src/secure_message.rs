// src/secure_message.rs
// Handles text message encryption/decryption with Sealed Sender and ephemeral keys

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, Secret};
use rand::rngs::OsRng;
use rand::RngCore;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Serialize, Deserialize};
use pqcrypto_dilithium::dilithium2;
use crate::hybrid_ratchet::HybridRatchet;
use crate::ephemeral_keys::{EphemeralKeyStore, verify_and_pin_ephemeral_key};

#[derive(Serialize, Deserialize)]
pub struct SecureMsg {
    header: Vec<u8>,
    nonce: [u8; 12],
    body: Vec<u8>,
    pq_ct: Option<Vec<u8>>,
    is_dummy: bool,
    ephemeral_pk: Vec<u8>,
    ephemeral_sig: Vec<u8>,
}

impl SecureMsg {
    pub fn encrypt(
        r: &mut HybridRatchet,
        peer_pq_pk: &pqcrypto_kyber::kyber768::PublicKey,
        identity_sk: &dilithium2::SecretKey,
        plaintext: &[u8],
        is_dummy: bool
    ) -> Result<SecureMsg> {
        let (header, _mklen) = r.dr.send(plaintext.len() as u32);
        r.send_ctr = r.send_ctr.wrapping_add(1);

        let pq_ct = if r.send_ctr % crate::hybrid_ratchet::PQ_REKEY_PERIOD == 0 {
            Some(r.pq_reencap(peer_pq_pk)?)
        } else { None };

        let ephemeral_sk = dilithium2::keypair().0;
        let ephemeral_pk = dilithium2::keypair().1.0.to_vec();

        let root = r.derive_root_key();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(root.expose_secret()));
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let mut flagged_plaintext = Vec::new();
        flagged_plaintext.push(if is_dummy {1} else {0});
        flagged_plaintext.extend_from_slice(plaintext);

        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), &flagged_plaintext)
            .context("text message encryption failed")?;

        let signature = dilithium2::sign(&ciphertext, &ephemeral_sk).0.to_vec();

        Ok(SecureMsg {
            header,
            nonce,
            body: ciphertext,
            pq_ct,
            is_dummy,
            ephemeral_pk,
            ephemeral_sig: signature,
        })
    }

    pub fn decrypt(
        r: &mut HybridRatchet,
        msg: &SecureMsg,
        sender_id: &str,
        ephemeral_store: &EphemeralKeyStore
    ) -> Result<Option<Vec<u8>>> {
        if let Some(ct) = &msg.pq_ct {
            r.pq_decaps(ct)?;
        }

        r.dr.recv(&msg.header)?;

        let root = r.derive_root_key();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(root.expose_secret()));
        let decrypted = cipher.decrypt(Nonce::from_slice(&msg.nonce), &msg.body)
            .context("text message decryption failed")?;

        let ephemeral_pk = dilithium2::PublicKey::from_bytes(&msg.ephemeral_pk)?;
        let signature = dilithium2::Signature::from_bytes(&msg.ephemeral_sig)?;
        dilithium2::verify(&msg.body, &signature, &ephemeral_pk)
            .map_err(|_| anyhow::anyhow!("ephemeral signature verification failed"))?;

        verify_and_pin_ephemeral_key(ephemeral_store, sender_id, &msg.ephemeral_pk)?;

        let is_dummy = decrypted[0] != 0;
        let plaintext = decrypted[1..].to_vec();

        if is_dummy {
            Ok(None)
        } else {
            Ok(Some(plaintext))
        }
    }
}
