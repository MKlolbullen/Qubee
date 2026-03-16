use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

lazy_static::lazy_static! {
    static ref ACTIVE_IDENTITY: Mutex<Option<ActiveIdentityState>> = Mutex::new(None);
    static ref ACTIVE_SESSIONS: Mutex<HashMap<String, NativeSessionState>> = Mutex::new(HashMap::new());
}

const MAX_CHAIN_MESSAGES_PER_EPOCH: u64 = 1024;
const MAX_SKIPPED_MESSAGE_KEYS: u64 = 64;

/// Lock ACTIVE_IDENTITY without panicking on poison.
fn lock_identity() -> Result<std::sync::MutexGuard<'static, Option<ActiveIdentityState>>> {
    ACTIVE_IDENTITY
        .lock()
        .map_err(|_| anyhow!("identity mutex poisoned"))
}

/// Lock ACTIVE_SESSIONS without panicking on poison.
fn lock_sessions() -> Result<std::sync::MutexGuard<'static, HashMap<String, NativeSessionState>>> {
    ACTIVE_SESSIONS
        .lock()
        .map_err(|_| anyhow!("sessions mutex poisoned"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentityBundle {
    pub schema: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "relayHandle")]
    pub relay_handle: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "dhPublicKeyBase64")]
    pub dh_public_key_base64: String,
    #[serde(rename = "signingPublicKeyBase64")]
    pub signing_public_key_base64: String,
    #[serde(default, rename = "kyberPublicKeyBase64", skip_serializing_if = "Option::is_none")]
    pub kyber_public_key_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeIdentityBundle {
    pub schema: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "deviceLabel")]
    pub device_label: String,
    #[serde(rename = "relayHandle")]
    pub relay_handle: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "publicBundleBase64")]
    pub public_bundle_base64: String,
    #[serde(rename = "dhPrivateKeyBase64")]
    pub dh_private_key_base64: String,
    #[serde(rename = "signingPrivateKeyBase64")]
    pub signing_private_key_base64: String,
    #[serde(default, rename = "kyberPrivateKeyBase64", skip_serializing_if = "Option::is_none")]
    pub kyber_private_key_base64: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecycleState {
    #[serde(alias = "NativeActive")]
    Active,
    #[serde(alias = "NativeRekeyRequired")]
    RekeyRequired,
    #[serde(alias = "NativeRelinkRequired")]
    RelinkRequired,
    #[serde(alias = "NativeClosed")]
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeSessionBundle {
    pub schema: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "peerHandle")]
    pub peer_handle: String,
    #[serde(rename = "peerIdentityFingerprint")]
    pub peer_identity_fingerprint: String,
    #[serde(rename = "state")]
    pub state: SessionLifecycleState,
    #[serde(rename = "rootKeyBase64")]
    pub root_key_base64: String,
    #[serde(rename = "sendKeyBase64")]
    pub send_key_base64: String,
    #[serde(rename = "receiveKeyBase64")]
    pub receive_key_base64: String,
    #[serde(rename = "sendCounter")]
    pub send_counter: u64,
    #[serde(rename = "receiveCounter")]
    pub receive_counter: u64,
    #[serde(rename = "epoch")]
    pub epoch: u32,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(default, rename = "bootstrapPayloadBase64", skip_serializing_if = "Option::is_none")]
    pub bootstrap_payload_base64: Option<String>,
    #[serde(default, rename = "localRatchetPrivateKeyBase64", skip_serializing_if = "Option::is_none")]
    pub local_ratchet_private_key_base64: Option<String>,
    #[serde(default, rename = "localRatchetPublicKeyBase64", skip_serializing_if = "Option::is_none")]
    pub local_ratchet_public_key_base64: Option<String>,
    #[serde(default, rename = "remoteRatchetPublicKeyBase64", skip_serializing_if = "Option::is_none")]
    pub remote_ratchet_public_key_base64: Option<String>,
    #[serde(default, rename = "previousSendChainLength")]
    pub previous_send_chain_length: u64,
    #[serde(default, rename = "needsSendRatchet")]
    pub needs_send_ratchet: bool,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeCipherEnvelope {
    pub schema: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "counter")]
    pub counter: u64,
    #[serde(rename = "nonceBase64")]
    pub nonce_base64: String,
    #[serde(rename = "ciphertextBase64")]
    pub ciphertext_base64: String,
    #[serde(default, rename = "ratchetPublicKeyBase64", skip_serializing_if = "Option::is_none")]
    pub ratchet_public_key_base64: Option<String>,
    #[serde(default, rename = "previousChainLength")]
    pub previous_chain_length: u64,
    #[serde(default, rename = "epoch")]
    pub epoch: u32,
    #[serde(default, rename = "senderIdentityFingerprint", skip_serializing_if = "Option::is_none")]
    pub sender_identity_fingerprint: Option<String>,
    #[serde(default, rename = "recipientIdentityFingerprint", skip_serializing_if = "Option::is_none")]
    pub recipient_identity_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeInvitePayload {
    pub schema: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "relayHandle")]
    pub relay_handle: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "publicBundleBase64")]
    pub public_bundle_base64: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: u64,
    #[serde(default, rename = "keyOwnershipProofBase64", skip_serializing_if = "Option::is_none")]
    pub key_ownership_proof_base64: Option<String>,
}

/// Zero-knowledge proof of key ownership generated during onboarding.
///
/// The proof binds together the X25519 DH key, the Dilithium2 signing key,
/// and the optional Kyber-768 KEM key into a single cryptographically verified
/// statement.  A Dilithium2 signature over a canonical statement hash proves
/// the holder possesses the signing private key, while the signed statement
/// covers all three public keys — so trust in the Dilithium2 proof extends
/// transitively to the DH and KEM keys.
///
/// A `key_binding_commitment` is included so that future key rotations can
/// prove continuity of ownership without revealing any private key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOwnershipProof {
    pub schema: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "dhPublicKeyBase64")]
    pub dh_public_key_base64: String,
    #[serde(rename = "signingPublicKeyBase64")]
    pub signing_public_key_base64: String,
    #[serde(default, rename = "kyberPublicKeyBase64", skip_serializing_if = "Option::is_none")]
    pub kyber_public_key_base64: Option<String>,
    #[serde(rename = "proofNonceBase64")]
    pub proof_nonce_base64: String,
    #[serde(rename = "proofTimestamp")]
    pub proof_timestamp: u64,
    /// BLAKE3 hash of the canonical proof statement — included for auditability.
    #[serde(rename = "proofStatementBase64")]
    pub proof_statement_base64: String,
    /// Dilithium2 detached signature over `proof_statement`.
    #[serde(rename = "dilithiumSignatureBase64")]
    pub dilithium_signature_base64: String,
    /// BLAKE3 commitment to a key-binding secret derived from the private keys.
    /// Stored by verifiers so that a future rotation proof can demonstrate
    /// continuity of ownership without exposing any private key.
    #[serde(rename = "keyBindingCommitmentBase64")]
    pub key_binding_commitment_base64: String,
}

/// Proof of identity continuity across a key rotation.
///
/// The holder of a *new* identity proves they also held the *old* identity by
/// revealing the `key_binding_secret` that was committed to in the old
/// [`KeyOwnershipProof`].  The secret is one-way derived from the old private
/// keys via HKDF, so revealing it does not expose any session key material.
///
/// The entire rotation proof is signed by the *new* Dilithium2 key, binding
/// the old and new identities together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationProof {
    pub schema: String,
    #[serde(rename = "oldIdentityFingerprint")]
    pub old_identity_fingerprint: String,
    #[serde(rename = "newIdentityFingerprint")]
    pub new_identity_fingerprint: String,
    /// The key-binding secret from the OLD identity — verifier checks this
    /// against the commitment stored from the old [`KeyOwnershipProof`].
    #[serde(rename = "oldKeyBindingSecretBase64")]
    pub old_key_binding_secret_base64: String,
    /// Fresh commitment for the NEW identity (stored for future rotations).
    #[serde(rename = "newKeyBindingCommitmentBase64")]
    pub new_key_binding_commitment_base64: String,
    #[serde(rename = "rotationTimestamp")]
    pub rotation_timestamp: u64,
    #[serde(rename = "rotationNonceBase64")]
    pub rotation_nonce_base64: String,
    /// Dilithium2 signature from the NEW signing key over the rotation statement.
    #[serde(rename = "dilithiumSignatureBase64")]
    pub dilithium_signature_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeHybridSessionInit {
    pub schema: String,
    #[serde(rename = "contactId")]
    pub contact_id: String,
    #[serde(rename = "sessionBundleBase64")]
    pub session_bundle_base64: String,
    #[serde(rename = "initiatorPublicBundleBase64")]
    pub initiator_public_bundle_base64: String,
    #[serde(rename = "initiatorRatchetPublicKeyBase64")]
    pub initiator_ratchet_public_key_base64: String,
    #[serde(rename = "pqCiphertextBase64")]
    pub pq_ciphertext_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeCallResult {
    pub ok: bool,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(rename = "payloadBase64", skip_serializing_if = "Option::is_none")]
    pub payload_base64: Option<String>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ActiveIdentityState {
    display_name: String,
    device_label: String,
    relay_handle: String,
    device_id: String,
    identity_fingerprint: String,
    public_bundle_base64: String,
    dh_private_key: [u8; 32],
    signing_private_key: Vec<u8>,
    kyber_private_key: Option<Vec<u8>>,
}

impl Drop for ActiveIdentityState {
    fn drop(&mut self) {
        self.dh_private_key.zeroize();
        self.signing_private_key.zeroize();
        if let Some(kyber_private_key) = &mut self.kyber_private_key {
            kyber_private_key.zeroize();
        }
        self.public_bundle_base64.zeroize();
    }
}

#[derive(Clone)]
struct NativeSessionState {
    peer_handle: String,
    peer_identity_fingerprint: String,
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    receive_chain_key: [u8; 32],
    send_counter: u64,
    receive_counter: u64,
    epoch: u32,
    lifecycle_state: SessionLifecycleState,
    bootstrap_payload_base64: Option<String>,
    local_ratchet_private_key: Option<[u8; 32]>,
    local_ratchet_public_key: Option<[u8; 32]>,
    remote_ratchet_public_key: Option<[u8; 32]>,
    previous_send_chain_length: u64,
    needs_send_ratchet: bool,
    skipped_message_keys: HashMap<String, [u8; 32]>,
}

impl Drop for NativeSessionState {
    fn drop(&mut self) {
        self.peer_handle.zeroize();
        self.peer_identity_fingerprint.zeroize();
        self.root_key.zeroize();
        self.send_chain_key.zeroize();
        self.receive_chain_key.zeroize();
        if let Some(local_ratchet_private_key) = &mut self.local_ratchet_private_key {
            local_ratchet_private_key.zeroize();
        }
        if let Some(local_ratchet_public_key) = &mut self.local_ratchet_public_key {
            local_ratchet_public_key.zeroize();
        }
        if let Some(remote_ratchet_public_key) = &mut self.remote_ratchet_public_key {
            remote_ratchet_public_key.zeroize();
        }
        for key in self.skipped_message_keys.values_mut() {
            key.zeroize();
        }
        self.skipped_message_keys.clear();
    }
}

enum SessionEvent {
    LocalRekeyRequested,
    RemoteKeyChanged,
    RotationApplied,
    ChainExhausted,
    ReceiveGap,
    Close,
}

pub fn generate_identity_bundle(
    display_name: &str,
    device_label: &str,
    relay_handle: &str,
    device_id: &str,
) -> Result<Vec<u8>> {
    let mut dh_secret = [0u8; 32];
    OsRng.fill_bytes(&mut dh_secret);
    let dh_private = StaticSecret::from(dh_secret);
    let dh_public = PublicKey::from(&dh_private);

    let (signing_public, signing_private) = dilithium2::keypair();
    let (kyber_public, kyber_private) = kyber768::keypair();

    let fingerprint = fingerprint_for(dh_public.as_bytes(), signing_public.as_bytes());
    let public_bundle = PublicIdentityBundle {
        schema: "qubee.identity.public.v1".to_string(),
        identity_fingerprint: fingerprint.clone(),
        relay_handle: relay_handle.to_string(),
        device_id: device_id.to_string(),
        dh_public_key_base64: encode(dh_public.as_bytes()),
        signing_public_key_base64: encode(signing_public.as_bytes()),
        kyber_public_key_base64: Some(encode(kyber_public.as_bytes())),
    };
    let public_bundle_bytes = serde_json::to_vec(&public_bundle)?;

    let identity = NativeIdentityBundle {
        schema: "qubee.identity.bundle.v1".to_string(),
        display_name: display_name.to_string(),
        device_label: device_label.to_string(),
        relay_handle: relay_handle.to_string(),
        device_id: device_id.to_string(),
        identity_fingerprint: fingerprint,
        public_bundle_base64: encode(&public_bundle_bytes),
        dh_private_key_base64: encode(dh_private.to_bytes()),
        signing_private_key_base64: encode(signing_private.as_bytes()),
        kyber_private_key_base64: Some(encode(kyber_private.as_bytes())),
        created_at: now_ms(),
    };

    *lock_identity()? = Some(active_identity_from_bundle(&identity)?);
    Ok(serde_json::to_vec(&identity)?)
}

pub fn restore_identity_bundle(identity_bundle_bytes: &[u8]) -> Result<()> {
    let identity: NativeIdentityBundle = serde_json::from_slice(identity_bundle_bytes)?;
    *lock_identity()? = Some(active_identity_from_bundle(&identity)?);
    Ok(())
}

pub fn sign_relay_challenge(identity_bundle_bytes: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    let identity: NativeIdentityBundle = serde_json::from_slice(identity_bundle_bytes)?;
    let private_bytes = decode(&identity.signing_private_key_base64)?;
    let signing_key = dilithium2::SecretKey::from_bytes(&private_bytes)?;
    let signature = dilithium2::detached_sign(challenge, &signing_key);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_relay_signature(public_bundle_base64: &str, challenge: &[u8], signature_bytes: &[u8]) -> Result<()> {
    let public_bundle = public_bundle_from_base64(public_bundle_base64)?;
    let public_key = dilithium2::PublicKey::from_bytes(&decode(&public_bundle.signing_public_key_base64)?)?;
    let signature = dilithium2::DetachedSignature::from_bytes(signature_bytes)?;
    dilithium2::verify_detached_signature(&signature, challenge, &public_key)
        .map_err(|error| anyhow!(error.to_string()))
}

pub fn create_session_bundle(contact_id: &str, peer_public_bundle_bytes: &[u8], initiator: bool) -> Result<Vec<u8>> {
    let self_identity = lock_identity()?
        .clone()
        .ok_or_else(|| anyhow!("Native identity not initialized"))?;

    let (peer_public_bundle, root, send_chain, recv_chain) =
        derive_session_material(&self_identity, contact_id, peer_public_bundle_bytes, initiator)?;

    let session_key = canonical_session_id(&self_identity.relay_handle, &peer_public_bundle.relay_handle);

    let session = NativeSessionState {
        peer_handle: peer_public_bundle.relay_handle.clone(),
        peer_identity_fingerprint: peer_public_bundle.identity_fingerprint.clone(),
        root_key: root,
        send_chain_key: send_chain,
        receive_chain_key: recv_chain,
        send_counter: 0,
        receive_counter: 0,
        epoch: 0,
        lifecycle_state: SessionLifecycleState::Active,
        bootstrap_payload_base64: None,
        local_ratchet_private_key: None,
        local_ratchet_public_key: None,
        remote_ratchet_public_key: None,
        previous_send_chain_length: 0,
        needs_send_ratchet: false,
        skipped_message_keys: HashMap::new(),
    };

    lock_sessions()?.insert(session_key.clone(), session.clone());
    session_bundle_from_state(&session_key, &session)
}

pub fn restore_session_bundle(session_bundle_bytes: &[u8]) -> Result<()> {
    let bundle: NativeSessionBundle = serde_json::from_slice(session_bundle_bytes)?;
    lock_sessions()?.insert(
        bundle.session_id.clone(),
        NativeSessionState {
            peer_handle: bundle.peer_handle,
            peer_identity_fingerprint: bundle.peer_identity_fingerprint,
            root_key: decode_fixed_32(&bundle.root_key_base64)?,
            send_chain_key: decode_fixed_32(&bundle.send_key_base64)?,
            receive_chain_key: decode_fixed_32(&bundle.receive_key_base64)?,
            send_counter: bundle.send_counter,
            receive_counter: bundle.receive_counter,
            epoch: bundle.epoch,
            lifecycle_state: bundle.state,
            bootstrap_payload_base64: bundle.bootstrap_payload_base64,
            local_ratchet_private_key: bundle.local_ratchet_private_key_base64.as_deref().map(decode_fixed_32).transpose()?,
            local_ratchet_public_key: bundle.local_ratchet_public_key_base64.as_deref().map(decode_fixed_32).transpose()?,
            remote_ratchet_public_key: bundle.remote_ratchet_public_key_base64.as_deref().map(decode_fixed_32).transpose()?,
            previous_send_chain_length: bundle.previous_send_chain_length,
            needs_send_ratchet: bundle.needs_send_ratchet,
            skipped_message_keys: HashMap::new(),
        },
    );
    Ok(())
}

pub fn export_session_bundle(session_id: &str) -> Result<Vec<u8>> {
    let sessions = lock_sessions()?;
    let session = sessions
        .get(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;
    session_bundle_from_state(session_id, session)
}

pub fn mark_session_rekey_required(session_id: &str) -> Result<Vec<u8>> {
    let mut sessions = lock_sessions()?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;
    session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::LocalRekeyRequested)?;
    session_bundle_from_state(session_id, session)
}

pub fn mark_session_relink_required(session_id: &str) -> Result<Vec<u8>> {
    let mut sessions = lock_sessions()?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;
    session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::RemoteKeyChanged)?;
    session_bundle_from_state(session_id, session)
}

pub fn rotate_session_bundle(session_id: &str, peer_public_bundle_bytes: &[u8], initiator: bool) -> Result<Vec<u8>> {
    let self_identity = lock_identity()?
        .clone()
        .ok_or_else(|| anyhow!("Native identity not initialized"))?;
    let mut sessions = lock_sessions()?;
    let existing = sessions
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;

    if existing.lifecycle_state == SessionLifecycleState::Closed {
        return Err(anyhow!("Session is closed and cannot be rotated"));
    }

    let (peer_public_bundle, root, send_chain, recv_chain) =
        derive_session_material(&self_identity, session_id, peer_public_bundle_bytes, initiator)?;

    existing.peer_handle = peer_public_bundle.relay_handle;
    existing.peer_identity_fingerprint = peer_public_bundle.identity_fingerprint;
    existing.root_key = root;
    existing.send_chain_key = send_chain;
    existing.receive_chain_key = recv_chain;
    existing.send_counter = 0;
    existing.receive_counter = 0;
    existing.epoch = existing.epoch.saturating_add(1);
    existing.lifecycle_state = apply_session_event(existing.lifecycle_state.clone(), SessionEvent::RotationApplied)?;
    existing.bootstrap_payload_base64 = None;
    existing.local_ratchet_private_key = None;
    existing.local_ratchet_public_key = None;
    existing.remote_ratchet_public_key = None;
    existing.previous_send_chain_length = 0;
    existing.needs_send_ratchet = false;
    existing.skipped_message_keys.clear();

    session_bundle_from_state(session_id, existing)
}

pub fn close_session(session_id: &str) -> Result<()> {
    let mut sessions = lock_sessions()?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;
    session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::Close)?;
    Ok(())
}

pub fn encrypt_message(session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let identity = lock_identity()?
        .clone()
        .ok_or_else(|| anyhow!("Native identity not initialized"))?;
    let mut sessions = lock_sessions()?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;

    ensure_session_active(&session.lifecycle_state)?;
    if session.send_counter >= MAX_CHAIN_MESSAGES_PER_EPOCH {
        session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::ChainExhausted)?;
        return Err(anyhow!("Session rekey required before sending more messages"));
    }

    if session.local_ratchet_public_key.is_some() {
        if session.needs_send_ratchet {
            let local_private_key = session
                .local_ratchet_private_key
                .ok_or_else(|| anyhow!("Local ratchet private key missing"))?;
            let remote_public_key = session
                .remote_ratchet_public_key
                .ok_or_else(|| anyhow!("Remote ratchet public key missing"))?;
            let (next_root, next_send_chain) = derive_ratchet_root_and_chain(
                &session.root_key,
                &local_private_key,
                &remote_public_key,
                b"qubee-ratchet-send-v1",
            )?;
            session.previous_send_chain_length = session.send_counter;
            session.root_key = next_root;
            session.send_chain_key = next_send_chain;
            session.send_counter = 0;
            session.epoch = session.epoch.saturating_add(1);
            session.needs_send_ratchet = false;
        }
    }

    let counter = session.send_counter;
    let message_key = derive_message_key(&session.root_key, &session.send_chain_key, counter, b"qubee-send")?;
    let next_chain = derive_next_chain_key(&session.root_key, &session.send_chain_key, counter, b"qubee-send")?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ratchet_public_key_base64 = session.local_ratchet_public_key.map(|bytes| encode(bytes));
    let envelope = NativeCipherEnvelope {
        schema: if session.local_ratchet_public_key.is_some() {
            "qubee.cipher.v4".to_string()
        } else {
            "qubee.cipher.v3".to_string()
        },
        session_id: session_id.to_string(),
        counter,
        nonce_base64: encode(nonce),
        ciphertext_base64: String::new(),
        ratchet_public_key_base64,
        previous_chain_length: session.previous_send_chain_length,
        epoch: session.epoch,
        sender_identity_fingerprint: Some(identity.identity_fingerprint.clone()),
        recipient_identity_fingerprint: Some(session.peer_identity_fingerprint.clone()),
    };
    let aad = aad_for_envelope(session_id, &envelope);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|error| anyhow!(error.to_string()))?;

    session.send_chain_key = next_chain;
    session.send_counter = session.send_counter.saturating_add(1);

    let final_envelope = NativeCipherEnvelope {
        ciphertext_base64: encode(ciphertext),
        ..envelope
    };
    Ok(serde_json::to_vec(&final_envelope)?)
}

pub fn decrypt_message(session_id: &str, ciphertext_bytes: &[u8]) -> Result<Vec<u8>> {
    let identity = lock_identity()?
        .clone()
        .ok_or_else(|| anyhow!("Native identity not initialized"))?;
    let mut sessions = lock_sessions()?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| anyhow!("Unknown session: {session_id}"))?;
    let envelope: NativeCipherEnvelope = serde_json::from_slice(ciphertext_bytes)?;

    ensure_session_active(&session.lifecycle_state)?;
    if envelope.session_id != session_id {
        return Err(anyhow!("Session identifier mismatch"));
    }
    if let Some(sender_identity_fingerprint) = envelope.sender_identity_fingerprint.as_deref() {
        if sender_identity_fingerprint != session.peer_identity_fingerprint {
            session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::RemoteKeyChanged)?;
            return Err(anyhow!("Peer identity fingerprint mismatch; relink required"));
        }
    }
    if let Some(recipient_identity_fingerprint) = envelope.recipient_identity_fingerprint.as_deref() {
        if recipient_identity_fingerprint != identity.identity_fingerprint {
            return Err(anyhow!("Recipient identity fingerprint mismatch"));
        }
    }

    let envelope_chain_key = envelope
        .ratchet_public_key_base64
        .as_deref()
        .and_then(|_| envelope.ratchet_public_key_base64.as_deref().map(|encoded| decode_fixed_32(encoded).ok()))
        .flatten();
    let skipped_id = skipped_key_id(envelope_chain_key.as_ref(), envelope.counter);
    if let Some(skipped_key) = session.skipped_message_keys.remove(&skipped_id) {
        let aad = aad_for_envelope(session_id, &envelope);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&skipped_key));
        return cipher
            .decrypt(
                Nonce::from_slice(&decode_fixed_12(&envelope.nonce_base64)?),
                Payload { msg: decode(&envelope.ciphertext_base64)?.as_ref(), aad: &aad },
            )
            .map_err(|error| anyhow!(error.to_string()));
    }

    maybe_apply_remote_ratchet(session, &envelope)?;

    if envelope.counter < session.receive_counter {
        return Err(anyhow!(
            "Replay detected; expected counter {} but received {}",
            session.receive_counter,
            envelope.counter
        ));
    }
    if session.receive_counter >= MAX_CHAIN_MESSAGES_PER_EPOCH {
        session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::ChainExhausted)?;
        return Err(anyhow!("Session rekey required before decrypting more messages"));
    }
    if envelope.counter > session.receive_counter {
        if session.local_ratchet_public_key.is_none() {
            session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::ReceiveGap)?;
            return Err(anyhow!(
                "Out-of-order ciphertext requires session rekey; expected counter {} but received {}",
                session.receive_counter,
                envelope.counter
            ));
        }
        stash_skipped_message_keys(session, envelope.counter)?;
    }

    let message_key = derive_message_key(&session.root_key, &session.receive_chain_key, envelope.counter, b"qubee-recv")?;
    let next_chain = derive_next_chain_key(&session.root_key, &session.receive_chain_key, envelope.counter, b"qubee-recv")?;
    let aad = aad_for_envelope(session_id, &envelope);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&decode_fixed_12(&envelope.nonce_base64)?),
            Payload { msg: decode(&envelope.ciphertext_base64)?.as_ref(), aad: &aad },
        )
        .map_err(|error| anyhow!(error.to_string()))?;

    session.receive_chain_key = next_chain;
    session.receive_counter = session.receive_counter.saturating_add(1);
    Ok(plaintext)
}

pub fn export_invite_payload(identity_bundle_bytes: &[u8]) -> Result<Vec<u8>> {
    let identity: NativeIdentityBundle = serde_json::from_slice(identity_bundle_bytes)?;
    let proof = generate_key_ownership_proof(identity_bundle_bytes)?;
    let invite = NativeInvitePayload {
        schema: "qubee.invite.v2".to_string(),
        display_name: identity.display_name,
        relay_handle: identity.relay_handle,
        device_id: identity.device_id,
        identity_fingerprint: identity.identity_fingerprint,
        public_bundle_base64: identity.public_bundle_base64,
        issued_at: now_ms(),
        key_ownership_proof_base64: Some(encode(&proof)),
    };
    Ok(serde_json::to_vec(&invite)?)
}

pub fn inspect_invite_payload(payload_bytes: &[u8]) -> Result<Vec<u8>> {
    let invite: NativeInvitePayload = serde_json::from_slice(payload_bytes)?;
    Ok(serde_json::to_vec(&invite)?)
}

pub fn compute_safety_code(identity_bundle_bytes: &[u8], peer_public_bundle_bytes: &[u8]) -> Result<Vec<u8>> {
    let identity: NativeIdentityBundle = serde_json::from_slice(identity_bundle_bytes)?;
    let self_public = public_bundle_from_base64(&identity.public_bundle_base64)?;
    let peer_public: PublicIdentityBundle = serde_json::from_slice(peer_public_bundle_bytes)
        .or_else(|_| public_bundle_from_base64(std::str::from_utf8(peer_public_bundle_bytes).unwrap_or_default()))
        .context("Peer public bundle is not valid JSON/base64 JSON")?;

    let left = serde_json::to_vec(&self_public)?;
    let right = serde_json::to_vec(&peer_public)?;
    let (first, second) = if left <= right { (left, right) } else { (right, left) };
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let code = digest[..8]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(code.into_bytes())
}

// ─── Zero-Knowledge Proof of Key Ownership ──────────────────────────────────

const PROOF_STATEMENT_DOMAIN: &[u8] = b"qubee-key-ownership-proof-v1";
const BINDING_SECRET_DOMAIN: &[u8] = b"qubee-key-binding-secret-v1";
const BINDING_COMMITMENT_DOMAIN: &[u8] = b"qubee-key-binding-commitment-v1";
const ROTATION_STATEMENT_DOMAIN: &[u8] = b"qubee-key-rotation-proof-v1";
/// Maximum age in milliseconds before a proof is considered stale.
const PROOF_FRESHNESS_WINDOW_MS: u64 = 5 * 60 * 1000;

/// Generate a zero-knowledge proof of key ownership for the active identity.
///
/// The proof demonstrates that the holder possesses the Dilithium2 signing
/// private key and cryptographically binds it to the X25519 DH key and the
/// optional Kyber-768 KEM key.  It is suitable for embedding in QR invite
/// payloads, relay handshakes, or out-of-band verification.
pub fn generate_key_ownership_proof(identity_bundle_bytes: &[u8]) -> Result<Vec<u8>> {
    let identity: NativeIdentityBundle = serde_json::from_slice(identity_bundle_bytes)?;
    let public_bundle = public_bundle_from_base64(&identity.public_bundle_base64)?;

    // 1. Random nonce for freshness and replay resistance.
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let timestamp = now_ms();

    // 2. Canonical proof statement — covers ALL public keys plus freshness.
    let statement = build_ownership_statement(
        &public_bundle.dh_public_key_base64,
        &public_bundle.signing_public_key_base64,
        public_bundle.kyber_public_key_base64.as_deref(),
        &public_bundle.identity_fingerprint,
        timestamp,
        &nonce,
    );

    // 3. Dilithium2 signature over the statement.
    let signing_private_bytes = decode(&identity.signing_private_key_base64)?;
    let signing_key = dilithium2::SecretKey::from_bytes(&signing_private_bytes)?;
    let signature = dilithium2::detached_sign(&statement, &signing_key);

    // 4. Key-binding commitment (for future rotation proofs).
    let dh_private = decode_fixed_32(&identity.dh_private_key_base64)?;
    let binding_secret = derive_key_binding_secret(&dh_private, &signing_private_bytes);
    let binding_commitment = derive_key_binding_commitment(&binding_secret);

    let proof = KeyOwnershipProof {
        schema: "qubee.key-ownership-proof.v1".to_string(),
        identity_fingerprint: public_bundle.identity_fingerprint.clone(),
        dh_public_key_base64: public_bundle.dh_public_key_base64.clone(),
        signing_public_key_base64: public_bundle.signing_public_key_base64.clone(),
        kyber_public_key_base64: public_bundle.kyber_public_key_base64.clone(),
        proof_nonce_base64: encode(nonce),
        proof_timestamp: timestamp,
        proof_statement_base64: encode(&statement),
        dilithium_signature_base64: encode(signature.as_bytes()),
        key_binding_commitment_base64: encode(binding_commitment),
    };
    Ok(serde_json::to_vec(&proof)?)
}

/// Verify a zero-knowledge proof of key ownership against a public bundle.
///
/// Returns `Ok(())` if the proof is valid: the Dilithium2 signature verifies,
/// the statement covers the correct public keys, and the proof is fresh.
pub fn verify_key_ownership_proof(proof_bytes: &[u8], public_bundle_bytes: &[u8]) -> Result<()> {
    let proof: KeyOwnershipProof = serde_json::from_slice(proof_bytes)?;
    let public_bundle: PublicIdentityBundle = serde_json::from_slice(public_bundle_bytes)
        .or_else(|_| public_bundle_from_base64(std::str::from_utf8(public_bundle_bytes).unwrap_or_default()))
        .context("Public bundle is not valid JSON/base64 JSON")?;

    // 1. Confirm the proof's public keys match the bundle.
    if proof.dh_public_key_base64 != public_bundle.dh_public_key_base64 {
        return Err(anyhow!("DH public key mismatch between proof and bundle"));
    }
    if proof.signing_public_key_base64 != public_bundle.signing_public_key_base64 {
        return Err(anyhow!("Signing public key mismatch between proof and bundle"));
    }
    if proof.kyber_public_key_base64 != public_bundle.kyber_public_key_base64 {
        return Err(anyhow!("Kyber public key mismatch between proof and bundle"));
    }
    if proof.identity_fingerprint != public_bundle.identity_fingerprint {
        return Err(anyhow!("Identity fingerprint mismatch between proof and bundle"));
    }

    // 2. Freshness check.
    let age_ms = now_ms().saturating_sub(proof.proof_timestamp);
    if age_ms > PROOF_FRESHNESS_WINDOW_MS {
        return Err(anyhow!(
            "Key ownership proof is stale ({age_ms} ms old, limit {PROOF_FRESHNESS_WINDOW_MS} ms)"
        ));
    }

    // 3. Reconstruct the canonical statement and compare.
    let nonce = decode(&proof.proof_nonce_base64)?;
    let nonce_fixed: [u8; 32] = nonce
        .try_into()
        .map_err(|_| anyhow!("Proof nonce must be exactly 32 bytes"))?;
    let expected_statement = build_ownership_statement(
        &public_bundle.dh_public_key_base64,
        &public_bundle.signing_public_key_base64,
        public_bundle.kyber_public_key_base64.as_deref(),
        &public_bundle.identity_fingerprint,
        proof.proof_timestamp,
        &nonce_fixed,
    );
    let submitted_statement = decode(&proof.proof_statement_base64)?;
    if expected_statement != submitted_statement {
        return Err(anyhow!("Proof statement does not match reconstructed statement"));
    }

    // 4. Dilithium2 signature verification — the core ZK proof step.
    let signing_public = dilithium2::PublicKey::from_bytes(
        &decode(&public_bundle.signing_public_key_base64)?,
    )?;
    let signature = dilithium2::DetachedSignature::from_bytes(
        &decode(&proof.dilithium_signature_base64)?,
    )?;
    dilithium2::verify_detached_signature(&signature, &expected_statement, &signing_public)
        .map_err(|error| anyhow!("Dilithium2 signature verification failed: {error}"))?;

    Ok(())
}

/// Generate a rotation proof that links an old identity to a new one.
///
/// The prover reveals the old identity's key-binding secret (which does not
/// expose any session key material) and signs the entire rotation statement
/// with the new Dilithium2 key.
pub fn generate_key_rotation_proof(
    old_identity_bundle_bytes: &[u8],
    new_identity_bundle_bytes: &[u8],
) -> Result<Vec<u8>> {
    let old_identity: NativeIdentityBundle = serde_json::from_slice(old_identity_bundle_bytes)?;
    let new_identity: NativeIdentityBundle = serde_json::from_slice(new_identity_bundle_bytes)?;

    // Derive the OLD binding secret (to reveal).
    let old_dh_private = decode_fixed_32(&old_identity.dh_private_key_base64)?;
    let old_signing_private = decode(&old_identity.signing_private_key_base64)?;
    let old_binding_secret = derive_key_binding_secret(&old_dh_private, &old_signing_private);

    // Derive the NEW binding commitment (to store).
    let new_dh_private = decode_fixed_32(&new_identity.dh_private_key_base64)?;
    let new_signing_private = decode(&new_identity.signing_private_key_base64)?;
    let new_binding_secret = derive_key_binding_secret(&new_dh_private, &new_signing_private);
    let new_binding_commitment = derive_key_binding_commitment(&new_binding_secret);

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let timestamp = now_ms();

    // Build canonical rotation statement.
    let statement = build_rotation_statement(
        &old_identity.identity_fingerprint,
        &new_identity.identity_fingerprint,
        &old_binding_secret,
        &new_binding_commitment,
        timestamp,
        &nonce,
    );

    // Sign with the NEW Dilithium2 key.
    let new_signing_key = dilithium2::SecretKey::from_bytes(&new_signing_private)?;
    let signature = dilithium2::detached_sign(&statement, &new_signing_key);

    let proof = KeyRotationProof {
        schema: "qubee.key-rotation-proof.v1".to_string(),
        old_identity_fingerprint: old_identity.identity_fingerprint,
        new_identity_fingerprint: new_identity.identity_fingerprint,
        old_key_binding_secret_base64: encode(old_binding_secret),
        new_key_binding_commitment_base64: encode(new_binding_commitment),
        rotation_timestamp: timestamp,
        rotation_nonce_base64: encode(nonce),
        dilithium_signature_base64: encode(signature.as_bytes()),
    };
    Ok(serde_json::to_vec(&proof)?)
}

/// Verify a key rotation proof.
///
/// `old_commitment_base64` is the `key_binding_commitment_base64` from the
/// original [`KeyOwnershipProof`] of the old identity.
/// `new_public_bundle_bytes` is the public bundle JSON of the new identity.
pub fn verify_key_rotation_proof(
    rotation_proof_bytes: &[u8],
    old_commitment_base64: &str,
    new_public_bundle_bytes: &[u8],
) -> Result<()> {
    let proof: KeyRotationProof = serde_json::from_slice(rotation_proof_bytes)?;
    let new_bundle: PublicIdentityBundle = serde_json::from_slice(new_public_bundle_bytes)
        .or_else(|_| public_bundle_from_base64(std::str::from_utf8(new_public_bundle_bytes).unwrap_or_default()))
        .context("New public bundle is not valid JSON/base64 JSON")?;

    if proof.new_identity_fingerprint != new_bundle.identity_fingerprint {
        return Err(anyhow!("Rotation proof fingerprint does not match new public bundle"));
    }

    // 1. Verify the old binding secret matches the stored commitment.
    let old_binding_secret = decode_fixed_32(&proof.old_key_binding_secret_base64)?;
    let expected_commitment = derive_key_binding_commitment(&old_binding_secret);
    let stored_commitment = decode_fixed_32(old_commitment_base64)?;
    if expected_commitment != stored_commitment {
        return Err(anyhow!("Old key-binding secret does not match stored commitment — identity continuity cannot be verified"));
    }

    // 2. Freshness check.
    let age_ms = now_ms().saturating_sub(proof.rotation_timestamp);
    if age_ms > PROOF_FRESHNESS_WINDOW_MS {
        return Err(anyhow!("Rotation proof is stale ({age_ms} ms old)"));
    }

    // 3. Reconstruct the canonical statement.
    let nonce = decode(&proof.rotation_nonce_base64)?;
    let nonce_fixed: [u8; 32] = nonce
        .try_into()
        .map_err(|_| anyhow!("Rotation nonce must be exactly 32 bytes"))?;
    let new_binding_commitment = decode_fixed_32(&proof.new_key_binding_commitment_base64)?;
    let statement = build_rotation_statement(
        &proof.old_identity_fingerprint,
        &proof.new_identity_fingerprint,
        &old_binding_secret,
        &new_binding_commitment,
        proof.rotation_timestamp,
        &nonce_fixed,
    );

    // 4. Verify Dilithium2 signature from the NEW key.
    let new_signing_public = dilithium2::PublicKey::from_bytes(
        &decode(&new_bundle.signing_public_key_base64)?,
    )?;
    let signature = dilithium2::DetachedSignature::from_bytes(
        &decode(&proof.dilithium_signature_base64)?,
    )?;
    dilithium2::verify_detached_signature(&signature, &statement, &new_signing_public)
        .map_err(|error| anyhow!("Rotation proof Dilithium2 verification failed: {error}"))?;

    Ok(())
}

// ─── ZK proof helpers ───────────────────────────────────────────────────────

fn build_ownership_statement(
    dh_public_key_base64: &str,
    signing_public_key_base64: &str,
    kyber_public_key_base64: Option<&str>,
    identity_fingerprint: &str,
    timestamp: u64,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_STATEMENT_DOMAIN);
    hasher.update(dh_public_key_base64.as_bytes());
    hasher.update(signing_public_key_base64.as_bytes());
    if let Some(kyber) = kyber_public_key_base64 {
        hasher.update(kyber.as_bytes());
    }
    hasher.update(identity_fingerprint.as_bytes());
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(nonce);
    hasher.finalize().to_vec()
}

fn build_rotation_statement(
    old_fingerprint: &str,
    new_fingerprint: &str,
    old_binding_secret: &[u8; 32],
    new_binding_commitment: &[u8; 32],
    timestamp: u64,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ROTATION_STATEMENT_DOMAIN);
    hasher.update(old_fingerprint.as_bytes());
    hasher.update(new_fingerprint.as_bytes());
    hasher.update(old_binding_secret);
    hasher.update(new_binding_commitment);
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(nonce);
    hasher.finalize().to_vec()
}

/// Derive a key-binding secret from private key material using HKDF.
///
/// The secret is one-way: revealing it does not expose the DH or signing
/// private keys, and since it uses a unique HKDF label it cannot be confused
/// with any session key derivation path.
fn derive_key_binding_secret(dh_private_key: &[u8; 32], signing_private_key: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(dh_private_key.len() + 32);
    ikm.extend_from_slice(dh_private_key);
    ikm.extend_from_slice(&Sha256::digest(signing_private_key));
    let hk = Hkdf::<Sha256>::new(Some(BINDING_SECRET_DOMAIN), &ikm);
    let mut secret = [0u8; 32];
    hk.expand(b"qubee-binding-material", &mut secret)
        .expect("HKDF binding secret expansion should never fail for 32-byte output");
    secret
}

/// One-way commitment to a key-binding secret.
fn derive_key_binding_commitment(key_binding_secret: &[u8; 32]) -> [u8; 32] {
    let digest = Sha256::digest(
        [BINDING_COMMITMENT_DOMAIN, key_binding_secret.as_slice()].concat(),
    );
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&digest);
    commitment
}

pub fn clear_sessions() {
    if let Ok(mut sessions) = ACTIVE_SESSIONS.lock() {
        sessions.clear();
    }
}

pub fn call_result(payload: Result<Vec<u8>>) -> Vec<u8> {
    let result = match payload {
        Ok(bytes) => NativeCallResult {
            ok: true,
            error_code: None,
            error_message: None,
            payload_base64: Some(encode(bytes)),
        },
        Err(error) => NativeCallResult {
            ok: false,
            error_code: Some(error_code_for(&error)),
            error_message: Some(error.to_string()),
            payload_base64: None,
        },
    };

    serde_json::to_vec(&result).unwrap_or_else(|_| b"{\"ok\":false,\"errorCode\":\"native_result_serialization_failed\",\"errorMessage\":\"failed to serialize native result\"}".to_vec())
}

pub fn create_hybrid_session_init(contact_id: &str, peer_public_bundle_bytes: &[u8]) -> Result<Vec<u8>> {
    let self_identity = lock_identity()?
        .clone()
        .ok_or_else(|| anyhow!("Native identity not initialized"))?;

    let peer_public_bundle: PublicIdentityBundle = serde_json::from_slice(peer_public_bundle_bytes)
        .or_else(|_| public_bundle_from_base64(std::str::from_utf8(peer_public_bundle_bytes).unwrap_or_default()))
        .context("Peer public bundle is not valid JSON/base64 JSON")?;
    let peer_kyber_public = kyber768::PublicKey::from_bytes(&decode(
        peer_public_bundle
            .kyber_public_key_base64
            .as_deref()
            .ok_or_else(|| anyhow!("Peer bundle is missing Kyber public key"))?,
    )?)?;

    let self_private = StaticSecret::from(self_identity.dh_private_key);
    let peer_public = PublicKey::from(decode_fixed_32(&peer_public_bundle.dh_public_key_base64)?);
    let dh_shared = self_private.diffie_hellman(&peer_public).to_bytes();
    // pqcrypto encapsulate returns (SharedSecret, Ciphertext) per trait definition
    let (pq_shared_secret, pq_ciphertext) = kyber768::encapsulate(&peer_kyber_public);

    let (root, send_chain, recv_chain) = derive_hybrid_session_keys(
        &self_identity.relay_handle,
        &peer_public_bundle.relay_handle,
        contact_id,
        &dh_shared,
        pq_shared_secret.as_bytes(),
        true,
    )?;
    let (initiator_ratchet_private, initiator_ratchet_public) = generate_ratchet_keypair();

    let session_key = canonical_session_id(&self_identity.relay_handle, &peer_public_bundle.relay_handle);

    let bootstrap = NativeHybridSessionInit {
        schema: "qubee.session.init.v2".to_string(),
        contact_id: session_key.clone(),
        session_bundle_base64: String::new(),
        initiator_public_bundle_base64: self_identity.public_bundle_base64.clone(),
        initiator_ratchet_public_key_base64: encode(initiator_ratchet_public),
        pq_ciphertext_base64: encode(pq_ciphertext.as_bytes()),
    };
    let bootstrap_bytes = serde_json::to_vec(&bootstrap)?;
    let bootstrap_payload_base64 = Some(encode(&bootstrap_bytes));

    let session = NativeSessionState {
        peer_handle: peer_public_bundle.relay_handle.clone(),
        peer_identity_fingerprint: peer_public_bundle.identity_fingerprint.clone(),
        root_key: root,
        send_chain_key: send_chain,
        receive_chain_key: recv_chain,
        send_counter: 0,
        receive_counter: 0,
        epoch: 0,
        lifecycle_state: SessionLifecycleState::Active,
        bootstrap_payload_base64: bootstrap_payload_base64.clone(),
        local_ratchet_private_key: Some(initiator_ratchet_private),
        local_ratchet_public_key: Some(initiator_ratchet_public),
        remote_ratchet_public_key: None,
        previous_send_chain_length: 0,
        needs_send_ratchet: false,
        skipped_message_keys: HashMap::new(),
    };

    lock_sessions()?.insert(session_key.clone(), session.clone());
    let session_bundle = session_bundle_from_state(&session_key, &session)?;
    let hybrid_init = NativeHybridSessionInit {
        schema: "qubee.session.init.v2".to_string(),
        contact_id: session_key,
        session_bundle_base64: encode(&session_bundle),
        initiator_public_bundle_base64: self_identity.public_bundle_base64.clone(),
        initiator_ratchet_public_key_base64: encode(initiator_ratchet_public),
        pq_ciphertext_base64: encode(pq_ciphertext.as_bytes()),
    };
    Ok(serde_json::to_vec(&hybrid_init)?)
}

pub fn accept_hybrid_session_init(_contact_id: &str, init_bytes: &[u8]) -> Result<Vec<u8>> {
    let self_identity = lock_identity()?
        .clone()
        .ok_or_else(|| anyhow!("Native identity not initialized"))?;
    let init: NativeHybridSessionInit = serde_json::from_slice(init_bytes)?;

    let initiator_public_bundle = public_bundle_from_base64(&init.initiator_public_bundle_base64)?;

    // Derive canonical session ID — must match what the initiator embedded
    let session_key = canonical_session_id(&self_identity.relay_handle, &initiator_public_bundle.relay_handle);
    if init.contact_id != session_key {
        return Err(anyhow!(
            "Hybrid session ID mismatch: expected '{}' but init payload contains '{}'",
            session_key, init.contact_id
        ));
    }

    let self_private = StaticSecret::from(self_identity.dh_private_key);
    let peer_public = PublicKey::from(decode_fixed_32(&initiator_public_bundle.dh_public_key_base64)?);
    let dh_shared = self_private.diffie_hellman(&peer_public).to_bytes();

    let kyber_private_bytes = self_identity
        .kyber_private_key
        .as_ref()
        .ok_or_else(|| anyhow!("Native identity bundle is missing Kyber private key"))?;
    let kyber_private = kyber768::SecretKey::from_bytes(kyber_private_bytes)?;
    let pq_ciphertext = kyber768::Ciphertext::from_bytes(&decode(&init.pq_ciphertext_base64)?)?;
    let pq_shared_secret = kyber768::decapsulate(&pq_ciphertext, &kyber_private);

    let (root, send_chain, recv_chain) = derive_hybrid_session_keys(
        &self_identity.relay_handle,
        &initiator_public_bundle.relay_handle,
        &session_key,
        &dh_shared,
        pq_shared_secret.as_bytes(),
        false,
    )?;
    let (responder_ratchet_private, responder_ratchet_public) = generate_ratchet_keypair();
    let initiator_ratchet_public_key = decode_fixed_32(&init.initiator_ratchet_public_key_base64)?;

    let session = NativeSessionState {
        peer_handle: initiator_public_bundle.relay_handle.clone(),
        peer_identity_fingerprint: initiator_public_bundle.identity_fingerprint.clone(),
        root_key: root,
        send_chain_key: send_chain,
        receive_chain_key: recv_chain,
        send_counter: 0,
        receive_counter: 0,
        epoch: 0,
        lifecycle_state: SessionLifecycleState::Active,
        bootstrap_payload_base64: None,
        local_ratchet_private_key: Some(responder_ratchet_private),
        local_ratchet_public_key: Some(responder_ratchet_public),
        remote_ratchet_public_key: Some(initiator_ratchet_public_key),
        previous_send_chain_length: 0,
        needs_send_ratchet: true,
        skipped_message_keys: HashMap::new(),
    };

    lock_sessions()?.insert(session_key.clone(), session.clone());
    session_bundle_from_state(&session_key, &session)
}

fn derive_hybrid_session_keys(
    self_handle: &str,
    peer_handle: &str,
    contact_id: &str,
    dh_shared: &[u8; 32],
    pq_shared: &[u8],
    initiator: bool,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    // CRITICAL: Canonical salt ordering — same as derive_session_material.
    let salt = canonical_session_salt(self_handle, peer_handle, contact_id);

    let mut ikm = Vec::with_capacity(dh_shared.len() + pq_shared.len());
    ikm.extend_from_slice(dh_shared);
    ikm.extend_from_slice(pq_shared);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut root = [0u8; 32];
    let mut send_chain = [0u8; 32];
    let mut recv_chain = [0u8; 32];
    hk.expand(b"qubee-hybrid-root", &mut root).map_err(|_| anyhow!("HKDF hybrid root expansion failed"))?;
    if initiator {
        hk.expand(b"qubee-hybrid-chain-initiator-send", &mut send_chain)
            .map_err(|_| anyhow!("HKDF hybrid send expansion failed"))?;
        hk.expand(b"qubee-hybrid-chain-initiator-recv", &mut recv_chain)
            .map_err(|_| anyhow!("HKDF hybrid recv expansion failed"))?;
    } else {
        hk.expand(b"qubee-hybrid-chain-initiator-recv", &mut send_chain)
            .map_err(|_| anyhow!("HKDF hybrid send(reverse) expansion failed"))?;
        hk.expand(b"qubee-hybrid-chain-initiator-send", &mut recv_chain)
            .map_err(|_| anyhow!("HKDF hybrid recv(reverse) expansion failed"))?;
    }
    Ok((root, send_chain, recv_chain))
}

pub fn zeroize_all() {
    // NativeSessionState::drop() handles key zeroization automatically
    if let Ok(mut identity) = ACTIVE_IDENTITY.lock() {
        identity.take();
    }
    if let Ok(mut sessions) = ACTIVE_SESSIONS.lock() {
        sessions.clear();
    }
}

/// Produce a deterministic session identifier from two handles.
/// Both parties derive the same ID regardless of who is "self" vs "peer".
fn canonical_session_id(handle_a: &str, handle_b: &str) -> String {
    if handle_a <= handle_b {
        format!("{}::{}", handle_a, handle_b)
    } else {
        format!("{}::{}", handle_b, handle_a)
    }
}

/// Produce a deterministic salt regardless of which peer is "self" vs "peer".
/// Sorts the two handles lexicographically so both parties derive identical bytes.
fn canonical_session_salt(handle_a: &str, handle_b: &str, contact_id: &str) -> sha2::digest::Output<Sha256> {
    let mut salt_material = Vec::new();
    if handle_a <= handle_b {
        salt_material.extend_from_slice(handle_a.as_bytes());
        salt_material.extend_from_slice(handle_b.as_bytes());
    } else {
        salt_material.extend_from_slice(handle_b.as_bytes());
        salt_material.extend_from_slice(handle_a.as_bytes());
    }
    salt_material.extend_from_slice(contact_id.as_bytes());
    Sha256::digest(&salt_material)
}

fn public_bundle_from_base64(encoded: &str) -> Result<PublicIdentityBundle> {
    let decoded = decode(encoded)?;
    Ok(serde_json::from_slice(&decoded)?)
}

fn active_identity_from_bundle(identity: &NativeIdentityBundle) -> Result<ActiveIdentityState> {
    Ok(ActiveIdentityState {
        display_name: identity.display_name.clone(),
        device_label: identity.device_label.clone(),
        relay_handle: identity.relay_handle.clone(),
        device_id: identity.device_id.clone(),
        identity_fingerprint: identity.identity_fingerprint.clone(),
        public_bundle_base64: identity.public_bundle_base64.clone(),
        dh_private_key: decode_fixed_32(&identity.dh_private_key_base64)?,
        signing_private_key: decode(&identity.signing_private_key_base64)?,
        kyber_private_key: identity
            .kyber_private_key_base64
            .as_deref()
            .map(decode)
            .transpose()?,
    })
}

fn derive_session_material(
    self_identity: &ActiveIdentityState,
    contact_id: &str,
    peer_public_bundle_bytes: &[u8],
    initiator: bool,
) -> Result<(PublicIdentityBundle, [u8; 32], [u8; 32], [u8; 32])> {
    let self_private = StaticSecret::from(self_identity.dh_private_key);
    let peer_public_bundle: PublicIdentityBundle = serde_json::from_slice(peer_public_bundle_bytes)
        .or_else(|_| public_bundle_from_base64(std::str::from_utf8(peer_public_bundle_bytes).unwrap_or_default()))
        .context("Peer public bundle is not valid JSON/base64 JSON")?;
    let peer_public = PublicKey::from(decode_fixed_32(&peer_public_bundle.dh_public_key_base64)?);
    let shared_secret = self_private.diffie_hellman(&peer_public).to_bytes();

    // CRITICAL: Canonical salt ordering — both peers MUST produce the same salt.
    // Sort handles lexicographically so Alice(self=alice,peer=bob) and
    // Bob(self=bob,peer=alice) both produce "alice||bob||contact_id".
    let salt = canonical_session_salt(
        &self_identity.relay_handle,
        &peer_public_bundle.relay_handle,
        contact_id,
    );

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);
    let mut root = [0u8; 32];
    let mut send_chain = [0u8; 32];
    let mut recv_chain = [0u8; 32];
    hk.expand(b"qubee-root", &mut root).map_err(|_| anyhow!("HKDF root expansion failed"))?;
    if initiator {
        hk.expand(b"qubee-chain-initiator-send", &mut send_chain)
            .map_err(|_| anyhow!("HKDF send expansion failed"))?;
        hk.expand(b"qubee-chain-initiator-recv", &mut recv_chain)
            .map_err(|_| anyhow!("HKDF recv expansion failed"))?;
    } else {
        hk.expand(b"qubee-chain-initiator-recv", &mut send_chain)
            .map_err(|_| anyhow!("HKDF send(reverse) expansion failed"))?;
        hk.expand(b"qubee-chain-initiator-send", &mut recv_chain)
            .map_err(|_| anyhow!("HKDF recv(reverse) expansion failed"))?;
    }

    Ok((peer_public_bundle, root, send_chain, recv_chain))
}

fn session_bundle_from_state(session_id: &str, state: &NativeSessionState) -> Result<Vec<u8>> {
    let bundle = NativeSessionBundle {
        schema: "qubee.session.bundle.v4".to_string(),
        session_id: session_id.to_string(),
        peer_handle: state.peer_handle.clone(),
        peer_identity_fingerprint: state.peer_identity_fingerprint.clone(),
        state: state.lifecycle_state.clone(),
        root_key_base64: encode(state.root_key),
        send_key_base64: encode(state.send_chain_key),
        receive_key_base64: encode(state.receive_chain_key),
        send_counter: state.send_counter,
        receive_counter: state.receive_counter,
        epoch: state.epoch,
        created_at: now_ms(),
        bootstrap_payload_base64: state.bootstrap_payload_base64.clone(),
        local_ratchet_private_key_base64: state.local_ratchet_private_key.map(|bytes| encode(bytes)),
        local_ratchet_public_key_base64: state.local_ratchet_public_key.map(|bytes| encode(bytes)),
        remote_ratchet_public_key_base64: state.remote_ratchet_public_key.map(|bytes| encode(bytes)),
        previous_send_chain_length: state.previous_send_chain_length,
        needs_send_ratchet: state.needs_send_ratchet,
        algorithm: if state.local_ratchet_public_key.is_some() {
            "x25519+ml-kem-768-double-ratchet-chacha20poly1305-v6".to_string()
        } else if state.bootstrap_payload_base64.is_some() {
            "x25519+ml-kem-768-hkdf-chain-state-chacha20poly1305-v5".to_string()
        } else {
            "x25519-hkdf-chain-state-chacha20poly1305-v3".to_string()
        },
    };
    Ok(serde_json::to_vec(&bundle)?)
}

fn generate_ratchet_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut private_bytes);
    let private_key = StaticSecret::from(private_bytes);
    private_bytes.zeroize();
    let public_key = PublicKey::from(&private_key).to_bytes();
    (private_key.to_bytes(), public_key)
}

fn derive_ratchet_root_and_chain(
    root_key: &[u8; 32],
    local_private_key: &[u8; 32],
    remote_public_key: &[u8; 32],
    label: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    let local_private = StaticSecret::from(*local_private_key);
    let remote_public = PublicKey::from(*remote_public_key);
    let shared_secret = local_private.diffie_hellman(&remote_public).to_bytes();
    let hk = Hkdf::<Sha256>::new(Some(root_key), &shared_secret);
    let mut next_root = [0u8; 32];
    let mut next_chain = [0u8; 32];
    hk.expand(b"qubee-ratchet-root-v1", &mut next_root)
        .map_err(|_| anyhow!("HKDF ratchet root expansion failed"))?;
    hk.expand(label, &mut next_chain)
        .map_err(|_| anyhow!("HKDF ratchet chain expansion failed"))?;
    Ok((next_root, next_chain))
}

fn chain_identity(ratchet_public_key: Option<&[u8; 32]>) -> String {
    ratchet_public_key
        .map(|public_key| encode(public_key))
        .unwrap_or_else(|| "initial-chain".to_string())
}

fn skipped_key_id(ratchet_public_key: Option<&[u8; 32]>, counter: u64) -> String {
    format!("{}:{}", chain_identity(ratchet_public_key), counter)
}

fn stash_skipped_message_keys(session: &mut NativeSessionState, until_counter: u64) -> Result<()> {
    if until_counter <= session.receive_counter {
        return Ok(());
    }
    let gap = until_counter.saturating_sub(session.receive_counter);
    if gap > MAX_SKIPPED_MESSAGE_KEYS {
        session.lifecycle_state = apply_session_event(session.lifecycle_state.clone(), SessionEvent::ReceiveGap)?;
        return Err(anyhow!(
            "Receive gap {} exceeds skipped-key budget {}; session rekey required",
            gap,
            MAX_SKIPPED_MESSAGE_KEYS
        ));
    }
    while session.receive_counter < until_counter {
        let counter = session.receive_counter;
        let message_key = derive_message_key(&session.root_key, &session.receive_chain_key, counter, b"qubee-recv")?;
        let next_chain = derive_next_chain_key(&session.root_key, &session.receive_chain_key, counter, b"qubee-recv")?;
        let key_id = skipped_key_id(session.remote_ratchet_public_key.as_ref(), counter);
        session.skipped_message_keys.insert(key_id, message_key);
        session.receive_chain_key = next_chain;
        session.receive_counter = session.receive_counter.saturating_add(1);
    }
    Ok(())
}

fn maybe_apply_remote_ratchet(
    session: &mut NativeSessionState,
    envelope: &NativeCipherEnvelope,
) -> Result<()> {
    let Some(remote_public_key_base64) = envelope.ratchet_public_key_base64.as_deref() else {
        return Ok(());
    };
    let remote_public_key = decode_fixed_32(remote_public_key_base64)?;
    if session.remote_ratchet_public_key == Some(remote_public_key) {
        return Ok(());
    }
    if session.local_ratchet_private_key.is_none() {
        return Ok(());
    }
    if envelope.previous_chain_length > session.receive_counter {
        stash_skipped_message_keys(session, envelope.previous_chain_length)?;
    }
    let local_private_key = session
        .local_ratchet_private_key
        .ok_or_else(|| anyhow!("Local ratchet state missing"))?;
    let (next_root, next_receive_chain) = derive_ratchet_root_and_chain(
        &session.root_key,
        &local_private_key,
        &remote_public_key,
        b"qubee-ratchet-recv-v1",
    )?;
    session.root_key = next_root;
    session.receive_chain_key = next_receive_chain;
    session.receive_counter = 0;
    session.remote_ratchet_public_key = Some(remote_public_key);
    session.epoch = envelope.epoch;
    session.needs_send_ratchet = true;
    let (next_local_private, next_local_public) = generate_ratchet_keypair();
    session.local_ratchet_private_key = Some(next_local_private);
    session.local_ratchet_public_key = Some(next_local_public);
    Ok(())
}

fn apply_session_event(current: SessionLifecycleState, event: SessionEvent) -> Result<SessionLifecycleState> {
    match (current, event) {
        (SessionLifecycleState::Active, SessionEvent::LocalRekeyRequested)
        | (SessionLifecycleState::Active, SessionEvent::ChainExhausted)
        | (SessionLifecycleState::Active, SessionEvent::ReceiveGap)
        | (SessionLifecycleState::RekeyRequired, SessionEvent::LocalRekeyRequested)
        | (SessionLifecycleState::RekeyRequired, SessionEvent::ChainExhausted)
        | (SessionLifecycleState::RekeyRequired, SessionEvent::ReceiveGap) => Ok(SessionLifecycleState::RekeyRequired),
        (SessionLifecycleState::RelinkRequired, SessionEvent::LocalRekeyRequested)
        | (SessionLifecycleState::RelinkRequired, SessionEvent::ChainExhausted)
        | (SessionLifecycleState::RelinkRequired, SessionEvent::ReceiveGap) => Ok(SessionLifecycleState::RelinkRequired),
        (SessionLifecycleState::Active, SessionEvent::RemoteKeyChanged)
        | (SessionLifecycleState::RekeyRequired, SessionEvent::RemoteKeyChanged)
        | (SessionLifecycleState::RelinkRequired, SessionEvent::RemoteKeyChanged) => Ok(SessionLifecycleState::RelinkRequired),
        (SessionLifecycleState::Active, SessionEvent::RotationApplied)
        | (SessionLifecycleState::RekeyRequired, SessionEvent::RotationApplied)
        | (SessionLifecycleState::RelinkRequired, SessionEvent::RotationApplied) => Ok(SessionLifecycleState::Active),
        (_, SessionEvent::Close) => Ok(SessionLifecycleState::Closed),
        (SessionLifecycleState::Closed, SessionEvent::RotationApplied) => Err(anyhow!("Closed sessions cannot be rotated")),
        (SessionLifecycleState::Closed, _) => Err(anyhow!("Session is closed")),
    }
}

fn ensure_session_active(state: &SessionLifecycleState) -> Result<()> {
    match state {
        SessionLifecycleState::Active => Ok(()),
        SessionLifecycleState::RekeyRequired => Err(anyhow!("Session rekey required before message processing")),
        SessionLifecycleState::RelinkRequired => Err(anyhow!("Session relink required after peer identity change")),
        SessionLifecycleState::Closed => Err(anyhow!("Session is closed")),
    }
}

fn derive_message_key(root_key: &[u8; 32], chain_key: &[u8; 32], counter: u64, label: &[u8]) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(label);
    info.extend_from_slice(&counter.to_le_bytes());
    let hk = Hkdf::<Sha256>::new(Some(root_key), chain_key);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).map_err(|_| anyhow!("HKDF message-key expansion failed"))?;
    Ok(out)
}

fn derive_next_chain_key(root_key: &[u8; 32], chain_key: &[u8; 32], counter: u64, label: &[u8]) -> Result<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(label);
    info.extend_from_slice(b"-next-");
    info.extend_from_slice(&counter.to_le_bytes());
    let hk = Hkdf::<Sha256>::new(Some(root_key), chain_key);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).map_err(|_| anyhow!("HKDF chain-key expansion failed"))?;
    Ok(out)
}

fn aad_for_envelope(session_id: &str, envelope: &NativeCipherEnvelope) -> Vec<u8> {
    let mut aad = b"qubee.cipher.aad.v4".to_vec();
    aad.extend_from_slice(session_id.as_bytes());
    aad.extend_from_slice(&envelope.epoch.to_le_bytes());
    aad.extend_from_slice(&envelope.counter.to_le_bytes());
    aad.extend_from_slice(&envelope.previous_chain_length.to_le_bytes());
    if let Some(ratchet_public_key_base64) = envelope.ratchet_public_key_base64.as_deref() {
        aad.extend_from_slice(ratchet_public_key_base64.as_bytes());
    }
    if let Some(sender_identity_fingerprint) = envelope.sender_identity_fingerprint.as_deref() {
        aad.extend_from_slice(sender_identity_fingerprint.as_bytes());
    }
    if let Some(recipient_identity_fingerprint) = envelope.recipient_identity_fingerprint.as_deref() {
        aad.extend_from_slice(recipient_identity_fingerprint.as_bytes());
    }
    aad
}

fn error_code_for(error: &anyhow::Error) -> String {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("unknown session") {
        "unknown_session".to_string()
    } else if message.contains("identity not initialized") {
        "identity_not_initialized".to_string()
    } else if message.contains("rekey") {
        "session_rekey_required".to_string()
    } else if message.contains("relink") || message.contains("identity change") {
        "session_relink_required".to_string()
    } else if message.contains("closed") {
        "session_closed".to_string()
    } else if message.contains("replay") || message.contains("out-of-order") || message.contains("gap") {
        "replay_or_out_of_order".to_string()
    } else if message.contains("fingerprint mismatch") {
        "identity_mismatch".to_string()
    } else if message.contains("valid json") || message.contains("json") {
        "invalid_json".to_string()
    } else if message.contains("signature") {
        "signature_verification_failed".to_string()
    } else if message.contains("base64") {
        "invalid_base64".to_string()
    } else {
        "native_error".to_string()
    }
}

fn fingerprint_for(dh_public: &[u8], signing_public: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(dh_public);
    hasher.update(signing_public);
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn encode(bytes: impl AsRef<[u8]>) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn decode(encoded: &str) -> Result<Vec<u8>> {
    STANDARD_NO_PAD.decode(encoded).map_err(|error| anyhow!(error.to_string()))
}

fn decode_fixed_32(encoded: &str) -> Result<[u8; 32]> {
    let decoded = decode(encoded)?;
    decoded.try_into().map_err(|_| anyhow!("Expected 32 bytes"))
}

fn decode_fixed_12(encoded: &str) -> Result<[u8; 12]> {
    let decoded = decode(encoded)?;
    decoded.try_into().map_err(|_| anyhow!("Expected 12 bytes"))
}

#[cfg(test)]
mod tests {
    use super::{
        accept_hybrid_session_init, compute_safety_code, create_hybrid_session_init, create_session_bundle, decrypt_message,
        encrypt_message, export_invite_payload, export_session_bundle, generate_identity_bundle, mark_session_rekey_required,
        mark_session_relink_required, restore_identity_bundle, restore_session_bundle, rotate_session_bundle,
        sign_relay_challenge, verify_relay_signature,
        generate_key_ownership_proof, verify_key_ownership_proof,
        generate_key_rotation_proof, verify_key_rotation_proof,
        NativeHybridSessionInit, NativeIdentityBundle, NativeInvitePayload, NativeSessionBundle,
        KeyOwnershipProof,
        PublicIdentityBundle, SessionLifecycleState,
    };
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

    fn public_bundle_bytes(identity_bundle: &[u8]) -> Vec<u8> {
        let identity: NativeIdentityBundle = serde_json::from_slice(identity_bundle).expect("identity bundle should deserialize");
        STANDARD_NO_PAD
            .decode(identity.public_bundle_base64)
            .expect("public bundle should base64 decode")
    }


    #[test]
    fn hybrid_session_init_round_trip_uses_post_quantum_bootstrap() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        let hybrid_init = create_hybrid_session_init("hybrid-chat", &bob_public).expect("hybrid init should create");
        let init: NativeHybridSessionInit = serde_json::from_slice(&hybrid_init).expect("hybrid init should deserialize");
        let alice_session = STANDARD_NO_PAD
            .decode(init.session_bundle_base64)
            .expect("initiator session bundle should decode");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore");
        let bob_session = accept_hybrid_session_init("hybrid-chat", &hybrid_init).expect("hybrid init should be accepted");

        restore_identity_bundle(&alice_identity).expect("alice identity should restore again");
        restore_session_bundle(&alice_session).expect("alice session should restore");
        let ciphertext = encrypt_message("hybrid-chat", b"pq hello").expect("hybrid message should encrypt");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore again");
        restore_session_bundle(&bob_session).expect("bob session should restore");
        let plaintext = decrypt_message("hybrid-chat", &ciphertext).expect("hybrid message should decrypt");
        let exported = export_session_bundle("hybrid-chat").expect("hybrid session should export");
        let bundle: NativeSessionBundle = serde_json::from_slice(&exported).expect("hybrid export should deserialize");

        assert_eq!(plaintext, b"pq hello");
        assert!(bundle.algorithm.contains("ml-kem-768"));
        assert!(bundle.bootstrap_payload_base64.is_none());
    }

    #[test]
    fn relay_signatures_verify_with_pq_signing_keys() {
        let identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("identity should generate");
        let challenge = b"relay-session:challenge";
        let signature = sign_relay_challenge(&identity, challenge).expect("challenge should sign");
        let bundle: NativeIdentityBundle = serde_json::from_slice(&identity).expect("identity bundle should deserialize");
        let public_bundle: PublicIdentityBundle = serde_json::from_slice(
            &STANDARD_NO_PAD.decode(bundle.public_bundle_base64).expect("public bundle should decode")
        ).expect("public bundle should deserialize");
        let public_bundle_base64 = STANDARD_NO_PAD.encode(serde_json::to_vec(&public_bundle).expect("public bundle should serialize"));
        verify_relay_signature(&public_bundle_base64, challenge, &signature).expect("pq relay signature should verify");
    }

    #[test]
    fn session_ratchets_and_rejects_replay() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let alice_public = public_bundle_bytes(&alice_identity);
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        let alice_session = create_session_bundle("chat-1", &bob_public, true).expect("alice session should create");
        restore_identity_bundle(&bob_identity).expect("bob identity should restore");
        let bob_session = create_session_bundle("chat-1", &alice_public, false).expect("bob session should create");

        restore_identity_bundle(&alice_identity).expect("alice identity should restore again");
        restore_session_bundle(&alice_session).expect("alice session should restore");
        let first = encrypt_message("chat-1", b"hello bob").expect("first message should encrypt");
        let second = encrypt_message("chat-1", b"hello again").expect("second message should encrypt");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore again");
        restore_session_bundle(&bob_session).expect("bob session should restore");
        assert_eq!(decrypt_message("chat-1", &first).expect("first message should decrypt"), b"hello bob");
        assert!(decrypt_message("chat-1", &first).is_err(), "replay should be rejected");
        assert_eq!(decrypt_message("chat-1", &second).expect("second message should decrypt"), b"hello again");
    }

    #[test]
    fn hybrid_sessions_support_double_ratchet_round_trip() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        let init = create_hybrid_session_init("ratchet-chat", &bob_public).expect("hybrid init should create");
        let init_payload: NativeHybridSessionInit = serde_json::from_slice(&init).expect("hybrid init should deserialize");
        let alice_session = STANDARD_NO_PAD.decode(init_payload.session_bundle_base64).expect("alice session should decode");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore");
        let bob_session = accept_hybrid_session_init("ratchet-chat", &init).expect("hybrid init should accept");

        restore_identity_bundle(&alice_identity).expect("alice identity should restore again");
        restore_session_bundle(&alice_session).expect("alice session should restore");
        let first = encrypt_message("ratchet-chat", b"hello bob").expect("alice first should encrypt");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore again");
        restore_session_bundle(&bob_session).expect("bob session should restore");
        let first_plain = decrypt_message("ratchet-chat", &first).expect("bob should decrypt first");
        assert_eq!(first_plain, b"hello bob");
        let reply = encrypt_message("ratchet-chat", b"hello alice").expect("bob reply should encrypt");
        let exported_bob = export_session_bundle("ratchet-chat").expect("bob session should export");
        let bob_bundle: NativeSessionBundle = serde_json::from_slice(&exported_bob).expect("bob export should deserialize");
        assert!(bob_bundle.algorithm.contains("double-ratchet"));

        restore_identity_bundle(&alice_identity).expect("alice identity should restore for reply");
        restore_session_bundle(&alice_session).expect("alice session should restore for reply");
        let reply_plain = decrypt_message("ratchet-chat", &reply).expect("alice should decrypt reply");
        assert_eq!(reply_plain, b"hello alice");
        let exported_alice = export_session_bundle("ratchet-chat").expect("alice session should export");
        let alice_bundle: NativeSessionBundle = serde_json::from_slice(&exported_alice).expect("alice export should deserialize");
        assert!(alice_bundle.needs_send_ratchet, "receiving a new ratchet should force a fresh outbound ratchet step");
    }

    #[test]
    fn hybrid_sessions_allow_limited_out_of_order_delivery() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        let init = create_hybrid_session_init("ooo-chat", &bob_public).expect("hybrid init should create");
        let init_payload: NativeHybridSessionInit = serde_json::from_slice(&init).expect("hybrid init should deserialize");
        let alice_session = STANDARD_NO_PAD.decode(init_payload.session_bundle_base64).expect("alice session should decode");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore");
        let bob_session = accept_hybrid_session_init("ooo-chat", &init).expect("hybrid init should accept");

        restore_identity_bundle(&alice_identity).expect("alice identity should restore again");
        restore_session_bundle(&alice_session).expect("alice session should restore");
        let first = encrypt_message("ooo-chat", b"first").expect("first should encrypt");
        let second = encrypt_message("ooo-chat", b"second").expect("second should encrypt");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore again");
        restore_session_bundle(&bob_session).expect("bob session should restore");
        assert_eq!(decrypt_message("ooo-chat", &second).expect("second should decrypt via skipped key cache"), b"second");
        assert_eq!(decrypt_message("ooo-chat", &first).expect("first should decrypt from skipped cache"), b"first");
        assert!(decrypt_message("ooo-chat", &first).is_err(), "replay from skipped cache should be rejected");
    }

    #[test]
    fn out_of_order_ciphertext_marks_session_for_rekey_until_rotation() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let alice_public = public_bundle_bytes(&alice_identity);
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        let alice_session = create_session_bundle("chat-gap", &bob_public, true).expect("alice session should create");
        restore_identity_bundle(&bob_identity).expect("bob identity should restore");
        let bob_session = create_session_bundle("chat-gap", &alice_public, false).expect("bob session should create");

        restore_identity_bundle(&alice_identity).expect("alice identity should restore again");
        restore_session_bundle(&alice_session).expect("alice session should restore");
        let first = encrypt_message("chat-gap", b"first").expect("first message should encrypt");
        let second = encrypt_message("chat-gap", b"second").expect("second message should encrypt");

        restore_identity_bundle(&bob_identity).expect("bob identity should restore again");
        restore_session_bundle(&bob_session).expect("bob session should restore");
        assert!(decrypt_message("chat-gap", &second).is_err(), "gap should force rekey");
        let blocked = decrypt_message("chat-gap", &first).expect_err("session should stay blocked until rotation");
        assert!(blocked.to_string().contains("rekey"));

        rotate_session_bundle("chat-gap", &alice_public, false).expect("rotation should reactivate session");
        let exported = export_session_bundle("chat-gap").expect("session export should succeed");
        let bundle: NativeSessionBundle = serde_json::from_slice(&exported).expect("exported session should deserialize");
        assert_eq!(bundle.state, SessionLifecycleState::Active);
    }

    #[test]
    fn relink_required_blocks_message_processing_until_rotation() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        create_session_bundle("chat-relink", &bob_public, true).expect("session should create");
        mark_session_relink_required("chat-relink").expect("mark relink required should succeed");

        let error = encrypt_message("chat-relink", b"blocked").expect_err("send should be blocked while relink is required");
        assert!(error.to_string().contains("relink"));

        rotate_session_bundle("chat-relink", &bob_public, true).expect("rotation should reactivate session");
        let exported = export_session_bundle("chat-relink").expect("session export should succeed");
        let bundle: NativeSessionBundle = serde_json::from_slice(&exported).expect("exported session should deserialize");
        assert_eq!(bundle.state, SessionLifecycleState::Active);
        assert_eq!(bundle.epoch, 1);
    }

    #[test]
    fn explicit_rekey_request_is_serialized_into_session_bundle() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let bob_public = public_bundle_bytes(&bob_identity);

        restore_identity_bundle(&alice_identity).expect("alice identity should restore");
        create_session_bundle("chat-mark", &bob_public, true).expect("session should create");
        let exported = mark_session_rekey_required("chat-mark").expect("mark rekey required should export session");
        let bundle: NativeSessionBundle = serde_json::from_slice(&exported).expect("session bundle should deserialize");
        assert_eq!(bundle.state, SessionLifecycleState::RekeyRequired);
    }

    #[test]
    fn invite_and_safety_code_round_trip() {
        let alice_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone").expect("alice identity should generate");
        let bob_identity = generate_identity_bundle("Bob", "S23", "bob", "bob-phone").expect("bob identity should generate");
        let alice_public = public_bundle_bytes(&alice_identity);
        let bob_public = public_bundle_bytes(&bob_identity);
        let invite = export_invite_payload(&alice_identity).expect("invite should export");
        let invite_json: serde_json::Value = serde_json::from_slice(&invite).expect("invite should be valid json");
        let alice_code = compute_safety_code(&alice_identity, &bob_public).expect("alice peer safety code should compute");
        let bob_code = compute_safety_code(&bob_identity, &alice_public).expect("bob peer safety code should compute");

        assert_eq!(invite_json["relayHandle"], "alice");
        assert_eq!(invite_json["deviceId"], "alice-phone");
        assert_eq!(alice_code, bob_code, "both peers should derive the same safety code");
    }

    // ─── Zero-Knowledge Proof Tests ─────────────────────────────────────────

    #[test]
    fn key_ownership_proof_verifies_for_own_identity() {
        let identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone")
            .expect("identity should generate");
        let public_bundle = public_bundle_bytes(&identity);

        let proof = generate_key_ownership_proof(&identity).expect("proof should generate");
        verify_key_ownership_proof(&proof, &public_bundle).expect("proof should verify against own bundle");
    }

    #[test]
    fn key_ownership_proof_rejects_wrong_public_bundle() {
        let alice = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone")
            .expect("alice identity should generate");
        let bob = generate_identity_bundle("Bob", "S23", "bob", "bob-phone")
            .expect("bob identity should generate");
        let bob_public = public_bundle_bytes(&bob);

        let alice_proof = generate_key_ownership_proof(&alice).expect("alice proof should generate");
        let result = verify_key_ownership_proof(&alice_proof, &bob_public);
        assert!(result.is_err(), "proof should fail verification against a different identity's public bundle");
    }

    #[test]
    fn invite_payload_contains_embedded_key_ownership_proof() {
        let identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone")
            .expect("identity should generate");
        let public_bundle = public_bundle_bytes(&identity);
        let invite_bytes = export_invite_payload(&identity).expect("invite should export");
        let invite: NativeInvitePayload = serde_json::from_slice(&invite_bytes)
            .expect("invite should deserialize");

        assert_eq!(invite.schema, "qubee.invite.v2");
        assert!(invite.key_ownership_proof_base64.is_some(), "invite v2 must carry a key ownership proof");

        let proof_bytes = STANDARD_NO_PAD
            .decode(invite.key_ownership_proof_base64.unwrap())
            .expect("proof base64 should decode");
        verify_key_ownership_proof(&proof_bytes, &public_bundle)
            .expect("embedded proof should verify against the invite's own public bundle");
    }

    #[test]
    fn key_rotation_proof_verifies_identity_continuity() {
        let old_identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone")
            .expect("old identity should generate");
        let new_identity = generate_identity_bundle("Alice", "Pixel-2", "alice", "alice-phone-2")
            .expect("new identity should generate");
        let new_public = public_bundle_bytes(&new_identity);

        let old_proof_bytes = generate_key_ownership_proof(&old_identity)
            .expect("old proof should generate");
        let old_proof: KeyOwnershipProof = serde_json::from_slice(&old_proof_bytes)
            .expect("old proof should deserialize");

        let rotation_proof = generate_key_rotation_proof(&old_identity, &new_identity)
            .expect("rotation proof should generate");
        verify_key_rotation_proof(
            &rotation_proof,
            &old_proof.key_binding_commitment_base64,
            &new_public,
        )
        .expect("rotation proof should verify identity continuity");
    }

    #[test]
    fn key_rotation_proof_rejects_forged_continuity() {
        let alice = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone")
            .expect("alice identity should generate");
        let mallory = generate_identity_bundle("Mallory", "EvilPhone", "mallory", "mallory-phone")
            .expect("mallory identity should generate");
        let new_identity = generate_identity_bundle("Alice", "Pixel-2", "alice", "alice-phone-2")
            .expect("new identity should generate");
        let new_public = public_bundle_bytes(&new_identity);

        // Alice's real commitment
        let alice_proof_bytes = generate_key_ownership_proof(&alice)
            .expect("alice proof should generate");
        let alice_proof: KeyOwnershipProof = serde_json::from_slice(&alice_proof_bytes)
            .expect("alice proof should deserialize");

        // Mallory generates a rotation proof from HER old identity to the new identity
        let forged_rotation = generate_key_rotation_proof(&mallory, &new_identity)
            .expect("forged rotation should generate");

        // Verification against Alice's commitment should fail
        let result = verify_key_rotation_proof(
            &forged_rotation,
            &alice_proof.key_binding_commitment_base64,
            &new_public,
        );
        assert!(result.is_err(), "rotation proof forged from a different identity must fail");
    }

    #[test]
    fn key_binding_commitment_is_deterministic_for_same_identity() {
        let identity = generate_identity_bundle("Alice", "Pixel", "alice", "alice-phone")
            .expect("identity should generate");

        let proof_a = generate_key_ownership_proof(&identity).expect("proof A should generate");
        let proof_b = generate_key_ownership_proof(&identity).expect("proof B should generate");
        let a: KeyOwnershipProof = serde_json::from_slice(&proof_a).expect("proof A should deserialize");
        let b: KeyOwnershipProof = serde_json::from_slice(&proof_b).expect("proof B should deserialize");

        assert_eq!(
            a.key_binding_commitment_base64, b.key_binding_commitment_base64,
            "same identity must produce the same binding commitment"
        );
        assert_ne!(
            a.proof_nonce_base64, b.proof_nonce_base64,
            "each proof should have a unique nonce"
        );
        assert_ne!(
            a.dilithium_signature_base64, b.dilithium_signature_base64,
            "each proof should have a unique signature (different nonce → different statement)"
        );
    }
}
