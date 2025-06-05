use anyhow::Result;
use tracing::info;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber768;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use crate::hybrid_ratchet::HybridRatchet;
use crate::ephemeral_keys::EphemeralKeyStore;
use crate::audio::{audio_sender_task, audio_receiver_task};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting PQ Messenger");

    // Key pairs
    let identity_sk = dilithium2::keypair().0;
    let identity_pk = dilithium2::keypair().1;

    let (kyber_sk, kyber_pk) = kyber768::keypair();

    // Session state
    let mut ratchet = HybridRatchet::new(true)?;
    let ephemeral_store: EphemeralKeyStore = Default::default();

    // Dummy peer
    let peer_addr = "127.0.0.1:9100";

    // UDP socket
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Start sender and receiver
    tokio::spawn(audio_sender_task(
        ratchet.clone(),
        peer_addr,
        identity_sk.clone(),
        udp_socket.clone(),
        true,  // enable dummy packets
        Some(15),
    ));

    tokio::spawn(audio_receiver_task(
        ratchet.clone(),
        "0.0.0.0:9100",
        "peer1",
        ephemeral_store.clone(),
        udp_socket.clone(),
    ));

    // Keep running
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
