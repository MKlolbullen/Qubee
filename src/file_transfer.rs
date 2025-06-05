use anyhow::{Result, Context};
use secrecy::ExposeSecret;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration};
use rand::Rng;
use pqcrypto_dilithium::dilithium2;
use crate::{HybridRatchet, PQ_REKEY_PERIOD};
use crate::ephemeral_keys::{EphemeralKeyStore, verify_and_pin_ephemeral_key};

const CHUNK_SIZE: usize = 65536;

#[derive(Serialize, Deserialize)]
pub struct FileChunk {
    pub file_id: u64,
    pub seq_number: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub pq_ct: Option<Vec<u8>>,
    pub is_dummy: bool,
    pub is_hash: bool,
    pub ephemeral_pk: Vec<u8>,
    pub ephemeral_sig: Vec<u8>,
}

pub async fn send_file(
    r: &mut HybridRatchet,
    peer_pq_pk: &pqcrypto_kyber::kyber768::PublicKey,
    file_path: &str,
    mut writer: tokio::io::WriteHalf<'_>,
    file_id: u64,
    enable_cover: bool,
    dummy_freq_secs: Option<u64>,
    identity_sk: &dilithium2::SecretKey
) -> Result<()> {
    let mut file = File::open(file_path).await.context("failed to open file")?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut seq = 0u32;
    let mut hasher = blake3::Hasher::new();

    if enable_cover {
        let freq = dummy_freq_secs.unwrap_or(15);
        let mut dummy_r = r.clone();
        let dummy_sk = identity_sk.clone();
        let mut dummy_writer = writer.clone();
        let dummy_peer_pk = peer_pq_pk.clone();
        tokio::spawn(async move {
            loop {
                let jitter = rand::thread_rng().gen_range(0..5);
                sleep(Duration::from_secs(freq + jitter)).await;
                if let Ok(dummy_chunk) = encrypt_chunk(&mut dummy_r, &dummy_peer_pk, file_id, seq, b"", true, false, &dummy_sk) {
                    let data = bincode::serialize(&dummy_chunk).unwrap();
                    let len = (data.len() as u32).to_be_bytes();
                    if dummy_writer.write_all(&len).await.is_err() { break; }
                    if dummy_writer.write_all(&data).await.is_err() { break; }
                    println!("Sent dummy file chunk seq {}", seq);
                }
                seq = seq.wrapping_add(1);
            }
        });
    }

    loop {
        let n = file.read(&mut buffer).await.context("file read error")?;
        if n == 0 { break; }

        hasher.update(&buffer[..n]);

        let chunk = encrypt_chunk(r, peer_pq_pk, file_id, seq, &buffer[..n], false, false, identity_sk)?;
        let data = bincode::serialize(&chunk).context("chunk serialization failed")?;
        let len = (data.len() as u32).to_be_bytes();
        writer.write_all(&len).await?;
        writer.write_all(&data).await?;

        seq = seq.wrapping_add(1);
    }

    let hash_output = hasher.finalize();
    let hash_bytes = hash_output.as_bytes();
    let hash_chunk = encrypt_chunk(r, peer_pq_pk, file_id, seq, hash_bytes, false, true, identity_sk)?;
    let data = bincode::serialize(&hash_chunk).context("hash chunk serialization failed")?;
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&data).await?;

    Ok(())
}

pub async fn receive_file(
    r: &mut HybridRatchet,
    mut reader: tokio::io::ReadHalf<'_>,
    output_path: &str,
    expected_file_id: u64,
    sender_id: &str,
    ephemeral_store: EphemeralKeyStore
) -> Result<()> {
    let mut file = File::create(output_path).await.context("failed to create output file")?;
    let mut hasher = blake3::Hasher::new();

    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).await.is_err() { break; }

        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        let mut chunk_buf = vec![0u8; chunk_len];
        reader.read_exact(&mut chunk_buf).await.context("chunk read failed")?;

        let chunk: FileChunk = bincode::deserialize(&chunk_buf).context("chunk deserialize failed")?;
        if chunk.file_id != expected_file_id { continue; }

        if let Some(ct) = &chunk.pq_ct {
            r.pq_decaps(ct)?;
        }

        let root = r.derive_root_key();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(root.expose_secret()));
        let decrypted = cipher.decrypt(Nonce::from_slice(&chunk.nonce), &chunk.ciphertext)
            .context("chunk decrypt failed")?;

        let ephemeral_pk = dilithium2::PublicKey::from_bytes(&chunk.ephemeral_pk)?;
        let signature = dilithium2::Signature::from_bytes(&chunk.ephemeral_sig)?;
        dilithium2::verify(&chunk.ciphertext, &signature, &ephemeral_pk)
            .map_err(|_| anyhow::anyhow!("signature verification failed"))?;

        verify_and_pin_ephemeral_key(&ephemeral_store, sender_id, &chunk.ephemeral_pk)?;

        if chunk.is_dummy {
            println!("Dropped dummy chunk seq {}", chunk.seq_number);
            continue;
        }

        if chunk.is_hash {
            let received_hash = decrypted;
            let calculated_hash = hasher.finalize();
            if received_hash == calculated_hash.as_bytes() {
                println!("✅ File integrity verified!");
            } else {
                eprintln!("❌ File integrity verification failed!");
                return Err(anyhow::anyhow!("File hash mismatch"));
            }
            break;
        }

        hasher.update(&decrypted);
        file.write_all(&decrypted).await.context("file write error")?;
    }

    Ok(())
}

fn encrypt_chunk(
    r: &mut HybridRatchet,
    peer_pq_pk: &pqcrypto_kyber::kyber768::PublicKey,
    file_id: u64,
    seq: u32,
    plaintext: &[u8],
    is_dummy: bool,
    is_hash: bool,
    identity_sk: &dilithium2::SecretKey
) -> Result<FileChunk> {
    r.send_ctr = r.send_ctr.wrapping_add(1);
    let pq_ct = if r.send_ctr % PQ_REKEY_PERIOD == 0 {
        Some(r.pq_reencap(peer_pq_pk)?)
    } else { None };

    let ephemeral_sk = dilithium2::keypair().0;
    let ephemeral_pk = dilithium2::keypair().1.0.to_vec();

    let root = r.derive_root_key();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(root.expose_secret()));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)
        .context("chunk encryption failed")?;

    let signature = dilithium2::sign(&ciphertext, &ephemeral_sk).0.to_vec();

    Ok(FileChunk {
        file_id,
        seq_number: seq,
        nonce,
        ciphertext,
        pq_ct,
        is_dummy,
        is_hash,
        ephemeral_pk,
        ephemeral_sig: signature,
    })
}
