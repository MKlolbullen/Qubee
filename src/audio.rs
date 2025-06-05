use anyhow::{Context, Result};
use secrecy::ExposeSecret;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use pqcrypto_dilithium::dilithium2;
use crate::{HybridRatchet, PQ_REKEY_PERIOD};
use crate::ephemeral_keys::{EphemeralKeyStore, verify_and_pin_ephemeral_key};
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use rand::Rng;

#[derive(Serialize, Deserialize)]
pub struct AudioPacket {
    pub version: u16,
    pub seq: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub ephemeral_pk: Vec<u8>,
    pub ephemeral_sig: Vec<u8>,
    pub is_dummy: bool,
}

pub fn encrypt_audio_packet(
    r: &mut HybridRatchet,
    plaintext: &[u8],
    version: u16,
    seq: u32,
    is_dummy: bool,
    identity_sk: &dilithium2::SecretKey
) -> Result<AudioPacket> {
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
        .context("audio packet encryption failed")?;

    let signature = dilithium2::sign(&ciphertext, &ephemeral_sk).0.to_vec();

    Ok(AudioPacket {
        version,
        seq,
        nonce,
        ciphertext,
        ephemeral_pk,
        ephemeral_sig: signature,
        is_dummy,
    })
}

pub fn decrypt_audio_packet(
    r: &mut HybridRatchet,
    packet: &AudioPacket,
    sender_id: &str,
    ephemeral_store: &EphemeralKeyStore
) -> Result<Option<Vec<u8>>> {
    let root = r.derive_root_key();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(root.expose_secret()));

    let decrypted = cipher.decrypt(Nonce::from_slice(&packet.nonce), &packet.ciphertext)
        .context("audio packet decrypt failed")?;

    let ephemeral_pk = dilithium2::PublicKey::from_bytes(&packet.ephemeral_pk)?;
    let signature = dilithium2::Signature::from_bytes(&packet.ephemeral_sig)?;
    dilithium2::verify(&packet.ciphertext, &signature, &ephemeral_pk)
        .map_err(|_| anyhow::anyhow!("ephemeral signature verification failed"))?;

    verify_and_pin_ephemeral_key(ephemeral_store, sender_id, &packet.ephemeral_pk)?;

    let is_dummy = decrypted[0] != 0;
    let audio_data = decrypted[1..].to_vec();

    if is_dummy {
        Ok(None)
    } else {
        Ok(Some(audio_data))
    }
}

pub async fn send_dummy_audio_packets(
    mut r: HybridRatchet,
    peer_addr: &str,
    identity_sk: dilithium2::SecretKey,
    udp_socket: UdpSocket,
    freq_secs: u64
) {
    let mut seq = 0u32;
    loop {
        let jitter = rand::thread_rng().gen_range(0..5);
        sleep(Duration::from_secs(freq_secs + jitter)).await;

        if let Ok(dummy_packet) = encrypt_audio_packet(&mut r, b"", 1, seq, true, &identity_sk) {
            let data = bincode::serialize(&dummy_packet).unwrap();
            if udp_socket.send_to(&data, peer_addr).await.is_err() {
                eprintln!("Failed to send dummy audio packet");
            } else {
                println!("Sent dummy audio packet seq {}", seq);
            }
        }

        seq = seq.wrapping_add(1);
    }
}
