//! Sender-keys group messaging (Ratchet Stage 4, dark-launched).
//!
//! The v3 group wire format. Each member maintains one **sender chain**
//! per group: a BLAKE3 hash ratchet whose per-message keys give forward
//! secrecy within the group — compromising a device reveals no message
//! sent before the compromise, unlike the v2 shared-symmetric-key
//! format where one key opens everything since the last rotation.
//!
//! ## Construction (Signal's sender-keys shape)
//!
//! * A member's [`SenderKeyDistribution`] carries their current chain
//!   key, iteration, and a **per-group ephemeral Ed25519 signing
//!   public**. It contains live key material and must therefore only
//!   ever travel inside an encrypted 1:1 channel — the Stage 3 Double
//!   Ratchet sessions ([`super::direct`]) are exactly that channel.
//! * Each group message is encrypted under the message key at the
//!   sender's current iteration and **signed with the ephemeral group
//!   signing key**. Every member holds every sender's chain key, so the
//!   AEAD alone cannot distinguish members — the signature is what
//!   stops member A forging messages as member B.
//! * This does **not** reintroduce the removed per-message identity
//!   signatures: the signing key is per-group, per-member, ephemeral,
//!   and bound to an identity only through the confidential (and itself
//!   deniable) 1:1 distribution. An outsider holding a transcript
//!   cannot link the signing key to anyone — messages stay deniable to
//!   outsiders while being authenticated inside the group.
//! * The sealed outer envelope from v2 is retained: the whole signed
//!   sender-key message is wrapped in an AEAD keyed off the (still
//!   rotated-on-membership-change) group key, so on-the-wire metadata
//!   stays limited to the group id and a nonce.
//!
//! ## Post-compromise / membership changes
//!
//! Removing a member must trigger [`reset_group_sender_state`] on every
//! remaining device plus fresh distributions all around — the removed
//! member holds everyone's chain keys. This mirrors (and rides on) the
//! existing v2 group-key rotation broadcast. Joining members receive
//! distributions snapshotted at the *current* iteration, so they cannot
//! read history.
//!
//! Same state-safety rule as the 1:1 path: receive state persists only
//! after a fully successful decrypt, and message keys are consumed on
//! use, so replays and garbage frames can neither open twice nor
//! corrupt the stored chain.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::groups::group_handshake::bounded_bincode_deserialize;
use crate::groups::group_manager::GroupId;
use crate::identity::identity_key::IdentityId;
use crate::security::secure_rng;
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};

/// Magic prefix for a v3 (sender-keys) group message frame. Coexists
/// with the v2 `\x02` symmetric format during the migration window.
pub const MAGIC_GROUP_MESSAGE_V3: &[u8] = b"QUBEE_GMS\x03";

const OUTER_V3_KDF_CONTEXT: &str = "qubee outer envelope v3";
const SENDER_MK_TAG: &[u8] = b"qubee_sender_mk_v1";
const SENDER_CK_TAG: &[u8] = b"qubee_sender_ck_v1";
const SENDER_MSG_KDF_INFO: &[u8] = b"qubee_sender_msg_aead_v1";
const SENDER_SIG_TAG: &[u8] = b"qubee_sender_sig_v1";
const SENDER_AAD_TAG: &[u8] = b"qubee_sender_aad_v1";

/// Maximum forward jump in a sender chain (mirrors the 1:1 ratchet's
/// skip window).
pub const SENDER_MAX_SKIP: u32 = 1000;
/// FIFO cap on retained skipped message keys per sender state.
const SENDER_MAX_SKIPPED_STORE: usize = 2000;

fn own_key_id(group: &GroupId) -> String {
    format!("sender_key_own_{}", hex::encode(group.as_bytes()))
}

fn recv_key_prefix(group: &GroupId) -> String {
    format!("sender_key_recv_{}_", hex::encode(group.as_bytes()))
}

fn recv_key_id(group: &GroupId, sender: &IdentityId) -> String {
    format!("{}{}", recv_key_prefix(group), hex::encode(sender.as_ref()))
}

fn state_metadata() -> KeyMetadata {
    KeyMetadata {
        algorithm: "sender-key-chain".to_string(),
        key_size: 32,
        usage: vec![KeyUsage::Encryption],
        expiry: None,
        tags: std::collections::HashMap::new(),
    }
}

/// One member's sender-key announcement for one group. **Contains the
/// live chain key** — never put this on the wire in plaintext; deliver
/// it through the Stage 3 encrypted 1:1 sessions only.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SenderKeyDistribution {
    pub group_id: GroupId,
    pub sender_id: IdentityId,
    /// Chain iteration this distribution starts at. Receivers can
    /// decrypt from here forward, never backward — late joiners get no
    /// history.
    pub iteration: u32,
    pub chain_key: [u8; 32],
    /// Per-group ephemeral Ed25519 verification key. Authenticates the
    /// sender *inside* the group without touching the identity keys.
    pub signing_pub: [u8; 32],
}

impl SenderKeyDistribution {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("serialize sender key distribution: {e}"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bounded_bincode_deserialize(bytes)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredOwnState {
    chain_key: [u8; 32],
    iteration: u32,
    signing_secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct StoredRecvState {
    chain_key: [u8; 32],
    iteration: u32,
    signing_pub: [u8; 32],
    /// Skipped (iteration, message key) pairs in FIFO insertion order.
    skipped: Vec<(u32, [u8; 32])>,
}

/// The signed inner message, sealed inside the outer envelope.
#[derive(Serialize, Deserialize)]
struct SenderKeyMessage {
    sender_id: IdentityId,
    iteration: u32,
    /// Inner AEAD ciphertext (key + nonce derived from the message key,
    /// which is unique per iteration, so no explicit nonce is carried).
    payload: Vec<u8>,
    /// Ed25519 signature by the sender's ephemeral group signing key.
    signature: Vec<u8>,
}

fn kdf_chain(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = *blake3::keyed_hash(ck, SENDER_MK_TAG).as_bytes();
    let next_ck = *blake3::keyed_hash(ck, SENDER_CK_TAG).as_bytes();
    (next_ck, mk)
}

fn derive_msg_aead(mk: &[u8; 32]) -> Result<([u8; 32], [u8; 12])> {
    let hk = Hkdf::<Sha256>::new(None, mk);
    let mut okm = [0u8; 44];
    hk.expand(SENDER_MSG_KDF_INFO, &mut okm)
        .map_err(|e| anyhow!("sender message KDF expand: {e}"))?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((key, nonce))
}

fn inner_aad(group: &GroupId, sender: &IdentityId, iteration: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SENDER_AAD_TAG.len() + 32 + 32 + 4);
    aad.extend_from_slice(SENDER_AAD_TAG);
    aad.extend_from_slice(group.as_bytes());
    aad.extend_from_slice(sender.as_ref());
    aad.extend_from_slice(&iteration.to_le_bytes());
    aad
}

fn signature_digest(
    group: &GroupId,
    sender: &IdentityId,
    iteration: u32,
    payload: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SENDER_SIG_TAG);
    h.update(group.as_bytes());
    h.update(sender.as_ref());
    h.update(&iteration.to_le_bytes());
    h.update(payload);
    *h.finalize().as_bytes()
}

fn load_own_state(ks: &mut SecureKeyStore, group: &GroupId) -> Result<Option<StoredOwnState>> {
    match ks.retrieve_key(&own_key_id(group))? {
        Some(secret) => Ok(Some(
            bincode::deserialize(secret.expose_secret())
                .map_err(|e| anyhow!("decode own sender state: {e}"))?,
        )),
        None => Ok(None),
    }
}

fn store_own_state(ks: &mut SecureKeyStore, group: &GroupId, state: &StoredOwnState) -> Result<()> {
    let bytes = bincode::serialize(state).map_err(|e| anyhow!("encode own sender state: {e}"))?;
    ks.store_key(
        &own_key_id(group),
        &bytes,
        KeyType::ChainKey,
        state_metadata(),
    )
}

fn load_recv_state(
    ks: &mut SecureKeyStore,
    group: &GroupId,
    sender: &IdentityId,
) -> Result<Option<StoredRecvState>> {
    match ks.retrieve_key(&recv_key_id(group, sender))? {
        Some(secret) => Ok(Some(
            bincode::deserialize(secret.expose_secret())
                .map_err(|e| anyhow!("decode recv sender state: {e}"))?,
        )),
        None => Ok(None),
    }
}

fn store_recv_state(
    ks: &mut SecureKeyStore,
    group: &GroupId,
    sender: &IdentityId,
    state: &StoredRecvState,
) -> Result<()> {
    let bytes = bincode::serialize(state).map_err(|e| anyhow!("encode recv sender state: {e}"))?;
    ks.store_key(
        &recv_key_id(group, sender),
        &bytes,
        KeyType::ChainKey,
        state_metadata(),
    )
}

/// Load — or create and persist — this device's sender key for `group`,
/// returning the distribution snapshot at the **current** iteration.
/// Call again after each membership change (the chain itself is fine to
/// re-announce; a *reset* needs [`reset_group_sender_state`] first).
pub fn create_or_get_own_sender_key(
    ks: &mut SecureKeyStore,
    group: &GroupId,
    local_id: IdentityId,
) -> Result<SenderKeyDistribution> {
    let state = match load_own_state(ks, group)? {
        Some(s) => s,
        None => {
            let state = StoredOwnState {
                chain_key: secure_rng::random::array::<32>()?,
                iteration: 0,
                signing_secret: secure_rng::random::array::<32>()?,
            };
            store_own_state(ks, group, &state)?;
            state
        }
    };
    let signing = SigningKey::from_bytes(&state.signing_secret);
    Ok(SenderKeyDistribution {
        group_id: *group,
        sender_id: local_id,
        iteration: state.iteration,
        chain_key: state.chain_key,
        signing_pub: signing.verifying_key().to_bytes(),
    })
}

/// Install a peer's sender key received over an **authenticated,
/// encrypted** channel. `authenticated_sender` is the identity the
/// carrying channel proved (e.g. the 1:1 session's peer) — it must
/// match the distribution's claim, or anyone could overwrite another
/// member's chain. Stale re-announcements of the same chain at an older
/// or equal iteration are rejected so a replay can't roll the chain
/// back to re-derivable (already-consumed) message keys.
pub fn install_sender_key(
    ks: &mut SecureKeyStore,
    authenticated_sender: IdentityId,
    dist: &SenderKeyDistribution,
) -> Result<()> {
    if dist.sender_id != authenticated_sender {
        bail!("sender key distribution claims a different sender than the delivering channel");
    }
    if let Some(existing) = load_recv_state(ks, &dist.group_id, &dist.sender_id)? {
        if existing.signing_pub == dist.signing_pub && dist.iteration <= existing.iteration {
            bail!("stale sender key distribution (chain already past this iteration)");
        }
    }
    let state = StoredRecvState {
        chain_key: dist.chain_key,
        iteration: dist.iteration,
        signing_pub: dist.signing_pub,
        skipped: Vec::new(),
    };
    store_recv_state(ks, &dist.group_id, &dist.sender_id, &state)
}

/// Encrypt `plaintext` for the group under this device's sender chain,
/// creating the chain on first use. The advanced chain state is
/// persisted **before** the frame is emitted, so a crash between the
/// two can only skip an iteration (receivers handle gaps), never reuse
/// a message key. `group_key` is the v2 rotating group key, used only
/// for the metadata-sealing outer envelope.
pub fn encrypt_sender_key_message(
    ks: &mut SecureKeyStore,
    group: &GroupId,
    group_key: &[u8; 32],
    local_id: IdentityId,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let inner = build_signed_inner(ks, group, local_id, plaintext)?;
    seal_outer_v3(group, group_key, &inner)
}

/// v5 variant of [`encrypt_sender_key_message`]: identical chain
/// advance and signed inner, but the outer envelope carries a keyed
/// selector instead of the plaintext group id (metadata parity with
/// the sealed v4 legacy envelope).
pub fn encrypt_sender_key_message_v5(
    ks: &mut SecureKeyStore,
    group: &GroupId,
    group_key: &[u8; 32],
    local_id: IdentityId,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let inner = build_signed_inner(ks, group, local_id, plaintext)?;
    seal_outer_v5(group_key, &inner)
}

fn build_signed_inner(
    ks: &mut SecureKeyStore,
    group: &GroupId,
    local_id: IdentityId,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    create_or_get_own_sender_key(ks, group, local_id)?;
    let mut state = load_own_state(ks, group)?.expect("own state just ensured");

    let iteration = state.iteration;
    let (next_ck, mut mk) = kdf_chain(&state.chain_key);
    state.chain_key = next_ck;
    state.iteration = iteration
        .checked_add(1)
        .ok_or_else(|| anyhow!("sender chain exhausted"))?;
    store_own_state(ks, group, &state)?;

    let (key, nonce) = derive_msg_aead(&mk)?;
    mk.zeroize();
    let cipher = ChaCha20Poly1305::new(&key.into());
    // Length-hiding: pad the plaintext to a size class before sealing so
    // the on-wire ciphertext length no longer fingerprints the message.
    let padded = crate::security::padding::pad(plaintext);
    let payload = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &padded,
                aad: &inner_aad(group, &local_id, iteration),
            },
        )
        .map_err(|e| anyhow!("sender message encrypt: {e}"))?;

    let signing = SigningKey::from_bytes(&state.signing_secret);
    let signature: Signature =
        signing.sign(&signature_digest(group, &local_id, iteration, &payload));

    bincode::serialize(&SenderKeyMessage {
        sender_id: local_id,
        iteration,
        payload,
        signature: signature.to_bytes().to_vec(),
    })
    .map_err(|e| anyhow!("serialize sender key message: {e}"))
}

/// Decrypt a v3 frame. Returns `(group_id, sender_id, plaintext)`.
/// Fails on: wrong/rotated group key (outer AEAD), unknown sender (no
/// distribution installed), bad signature (member forgery), replay
/// (consumed message key), or a skip beyond [`SENDER_MAX_SKIP`].
pub fn decrypt_sender_key_message(
    ks: &mut SecureKeyStore,
    group_key: &[u8; 32],
    wire: &[u8],
) -> Result<(GroupId, IdentityId, Vec<u8>)> {
    let (group, inner) = open_outer_v3(group_key, wire)?;
    open_signed_inner(ks, group, &inner)
}

/// Decrypt a v5 frame by trial-matching the keyed selector against
/// every candidate group key (see [`open_outer_v5`]); the inner
/// verification pipeline is identical to v3. The group is
/// authenticated, not asserted: only the right group key opens the
/// outer AEAD, and the signature digest + inner AAD re-bind the
/// matched group id at every layer below.
pub fn decrypt_sender_key_message_v5(
    ks: &mut SecureKeyStore,
    candidates: impl IntoIterator<Item = (GroupId, [u8; 32])>,
    wire: &[u8],
) -> Result<(GroupId, IdentityId, Vec<u8>)> {
    let (group, inner) = open_outer_v5(candidates, wire)?;
    open_signed_inner(ks, group, &inner)
}

fn open_signed_inner(
    ks: &mut SecureKeyStore,
    group: GroupId,
    inner: &[u8],
) -> Result<(GroupId, IdentityId, Vec<u8>)> {
    let msg: SenderKeyMessage = bounded_bincode_deserialize(inner)?;

    let mut state = load_recv_state(ks, &group, &msg.sender_id)?
        .ok_or_else(|| anyhow!("no sender key installed for this group member"))?;

    let verifying = VerifyingKey::from_bytes(&state.signing_pub)
        .map_err(|e| anyhow!("stored signing key invalid: {e}"))?;
    let sig_bytes: [u8; 64] = msg
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("malformed signature length"))?;
    verifying
        .verify(
            &signature_digest(&group, &msg.sender_id, msg.iteration, &msg.payload),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| anyhow!("sender key signature verification failed"))?;

    let mut mk = take_message_key(&mut state, msg.iteration)?;
    let (key, nonce) = derive_msg_aead(&mk)?;
    mk.zeroize();
    let cipher = ChaCha20Poly1305::new(&key.into());
    let padded = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &msg.payload,
                aad: &inner_aad(&group, &msg.sender_id, msg.iteration),
            },
        )
        .map_err(|_| anyhow!("sender message decrypt failed (tamper)"))?;
    let plaintext = crate::security::padding::unpad(&padded)?;

    store_recv_state(ks, &group, &msg.sender_id, &state)?;
    Ok((group, msg.sender_id, plaintext))
}

/// Advance (or reach back into the skipped store of) a receive chain to
/// produce the message key for `iteration`, consuming it. The caller
/// persists the mutated state only after the AEAD also succeeds.
fn take_message_key(state: &mut StoredRecvState, iteration: u32) -> Result<[u8; 32]> {
    if iteration < state.iteration {
        if let Some(pos) = state.skipped.iter().position(|(n, _)| *n == iteration) {
            let (_, mk) = state.skipped.remove(pos);
            return Ok(mk);
        }
        bail!("message key already consumed (replay?)");
    }
    if iteration - state.iteration > SENDER_MAX_SKIP {
        bail!(
            "sender chain skip too large ({} > {})",
            iteration - state.iteration,
            SENDER_MAX_SKIP
        );
    }
    while state.iteration < iteration {
        let (next_ck, skipped_mk) = kdf_chain(&state.chain_key);
        state.skipped.push((state.iteration, skipped_mk));
        if state.skipped.len() > SENDER_MAX_SKIPPED_STORE {
            let (_, mut evicted) = state.skipped.remove(0);
            evicted.zeroize();
        }
        state.chain_key = next_ck;
        state.iteration += 1;
    }
    let (next_ck, mk) = kdf_chain(&state.chain_key);
    state.chain_key = next_ck;
    state.iteration += 1;
    Ok(mk)
}

/// Iteration of this device's own sender chain for `group`, or `None`
/// when no chain exists yet (never sent, or wiped by
/// [`reset_group_sender_state`]). The send orchestrator uses `0`/`None`
/// as the "nobody holds my current chain" signal to trigger a
/// distribution fan-out before the first frame — which also covers
/// post-rekey redistribution, since a reset chain restarts at 0.
pub fn own_chain_iteration(ks: &mut SecureKeyStore, group: &GroupId) -> Result<Option<u32>> {
    Ok(load_own_state(ks, group)?.map(|s| s.iteration))
}

/// Wipe all sender-key state for a group (own chain + every installed
/// peer chain). Call on membership change — a removed member holds
/// everyone's chain keys, so all of them must be re-generated and
/// re-distributed. Returns how many states were deleted.
pub fn reset_group_sender_state(ks: &mut SecureKeyStore, group: &GroupId) -> Result<usize> {
    let own = own_key_id(group);
    let prefix = recv_key_prefix(group);
    let doomed: Vec<String> = ks
        .list_keys()
        .into_iter()
        .filter(|k| k == &own || k.starts_with(&prefix))
        .collect();
    let mut deleted = 0;
    for key in doomed {
        if ks.delete_key(&key)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Cheap dispatcher probe for the v3 magic.
pub fn is_group_message_v3_frame(wire: &[u8]) -> bool {
    wire.len() >= MAGIC_GROUP_MESSAGE_V3.len()
        && &wire[..MAGIC_GROUP_MESSAGE_V3.len()] == MAGIC_GROUP_MESSAGE_V3
}

/// Deterministic 16-byte id for a v3 sender-key message, derived from
/// group + sender + iteration + inner ciphertext. Sender and receiver
/// compute the same id from the same frame, so it correlates a
/// delivery `MessageAck` back to the sent row — the v3 analogue of
/// `group_message_id` for the v2 path.
pub fn v3_message_id(
    group: &GroupId,
    sender: &IdentityId,
    iteration: u32,
    payload: &[u8],
) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(b"qubee_group_message_v3_id_v1");
    h.update(group.as_bytes());
    h.update(sender.as_ref());
    h.update(&iteration.to_le_bytes());
    h.update(payload);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize().as_bytes()[..16]);
    out
}

/// Open a sealed v3 frame with `group_key` and compute its
/// [`v3_message_id`]. `None` if the bytes aren't a valid v3 envelope
/// under this key.
pub fn extract_v3_message_id(group_key: &[u8; 32], wire: &[u8]) -> Option<[u8; 16]> {
    let (group, inner) = open_outer_v3(group_key, wire).ok()?;
    let msg: SenderKeyMessage = bounded_bincode_deserialize(&inner).ok()?;
    Some(v3_message_id(
        &group,
        &msg.sender_id,
        msg.iteration,
        &msg.payload,
    ))
}

/// Read the (plaintext, but AD-bound) group id off a v3 frame without
/// any keys — the dispatcher needs it to look up the group key that
/// [`decrypt_sender_key_message`] requires. `None` if the frame is not
/// v3 or is truncated.
pub fn peek_v3_group_id(wire: &[u8]) -> Option<GroupId> {
    if !is_group_message_v3_frame(wire) {
        return None;
    }
    let magic_len = MAGIC_GROUP_MESSAGE_V3.len();
    if wire.len() < magic_len + 32 {
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&wire[magic_len..magic_len + 32]);
    Some(GroupId::from_bytes(bytes))
}

fn derive_outer_v3_key(group_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(OUTER_V3_KDF_CONTEXT, group_key)
}

/// `MAGIC || group_id(32) || nonce(12) || outer_ciphertext`. Same
/// metadata posture as v2: only the group id (already public via the
/// gossipsub topic) and a nonce are plaintext.
fn seal_outer_v3(group: &GroupId, group_key: &[u8; 32], inner: &[u8]) -> Result<Vec<u8>> {
    let outer_key = derive_outer_v3_key(group_key);
    let nonce_bytes = secure_rng::random::array::<12>()?;
    let cipher = ChaCha20Poly1305::new(&outer_key.into());
    let mut aad = Vec::with_capacity(MAGIC_GROUP_MESSAGE_V3.len() + 32);
    aad.extend_from_slice(MAGIC_GROUP_MESSAGE_V3);
    aad.extend_from_slice(group.as_bytes());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: inner,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("outer v3 seal: {e}"))?;

    let mut out = Vec::with_capacity(MAGIC_GROUP_MESSAGE_V3.len() + 32 + 12 + ciphertext.len());
    out.extend_from_slice(MAGIC_GROUP_MESSAGE_V3);
    out.extend_from_slice(group.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_outer_v3(group_key: &[u8; 32], wire: &[u8]) -> Result<(GroupId, Vec<u8>)> {
    let magic_len = MAGIC_GROUP_MESSAGE_V3.len();
    if wire.len() < magic_len + 32 + 12 {
        bail!("v3 frame too short");
    }
    if &wire[..magic_len] != MAGIC_GROUP_MESSAGE_V3 {
        bail!("not a v3 group message frame");
    }
    let mut group_bytes = [0u8; 32];
    group_bytes.copy_from_slice(&wire[magic_len..magic_len + 32]);
    let group = GroupId::from_bytes(group_bytes);
    let nonce = &wire[magic_len + 32..magic_len + 32 + 12];
    let ciphertext = &wire[magic_len + 32 + 12..];

    let outer_key = derive_outer_v3_key(group_key);
    let cipher = ChaCha20Poly1305::new(&outer_key.into());
    let mut aad = Vec::with_capacity(magic_len + 32);
    aad.extend_from_slice(MAGIC_GROUP_MESSAGE_V3);
    aad.extend_from_slice(group.as_bytes());
    let inner = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("outer v3 open failed (wrong or rotated group key)"))?;
    Ok((group, inner))
}

/// v5 sender-key wire format: `MAGIC || nonce(12) || selector(8) ||
/// outer_ciphertext` — metadata parity with the sealed v4 legacy
/// envelope. v3 (the first sender-keys format) put the 32-byte group
/// id on the wire in the clear, which both fingerprints a group's
/// traffic across messages and undoes what blinded rotating topics
/// hide. v5 replaces it with a keyed, per-message selector only a
/// group-key-holder can compute; receivers trial-match it across
/// their groups (one BLAKE3 per candidate, AEAD only on a hit).
pub const MAGIC_GROUP_MESSAGE_V5: &[u8] = b"QUBEE_GMS\x05";

/// Distinct from both the v3 outer-key context and the v4 selector
/// context ("qubee group selector v1"): a v4 selector must never
/// validate a v5 frame or vice versa, even under the same group key.
const V5_SELECTOR_KDF_CONTEXT: &str = "qubee sender-key group selector v1";
const OUTER_V5_KDF_CONTEXT: &str = "qubee sender-key outer envelope v5";

/// Same length/collision trade-off as the v4 envelope's selector.
pub const V5_SELECTOR_LEN: usize = 8;

/// Keyed per-message selector: `keyed_hash(derive_key(ctx, group_key),
/// nonce)`, truncated. Deterministic for a key-holder, opaque junk for
/// everyone else.
pub fn v5_group_selector(group_key: &[u8; 32], nonce: &[u8; 12]) -> [u8; V5_SELECTOR_LEN] {
    let selector_key = blake3::derive_key(V5_SELECTOR_KDF_CONTEXT, group_key);
    let full = blake3::keyed_hash(&selector_key, nonce);
    let mut out = [0u8; V5_SELECTOR_LEN];
    out.copy_from_slice(&full.as_bytes()[..V5_SELECTOR_LEN]);
    out
}

fn derive_outer_v5_key(group_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(OUTER_V5_KDF_CONTEXT, group_key)
}

fn seal_outer_v5(group_key: &[u8; 32], inner: &[u8]) -> Result<Vec<u8>> {
    let outer_key = derive_outer_v5_key(group_key);
    let nonce_bytes = secure_rng::random::array::<12>()?;
    let selector = v5_group_selector(group_key, &nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&outer_key.into());
    // The selector is the associated data: a captured ciphertext can't
    // be re-published under a different selector, mirroring how v3
    // bound the plaintext group id.
    let mut aad = Vec::with_capacity(MAGIC_GROUP_MESSAGE_V5.len() + V5_SELECTOR_LEN);
    aad.extend_from_slice(MAGIC_GROUP_MESSAGE_V5);
    aad.extend_from_slice(&selector);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: inner,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("outer v5 seal: {e}"))?;

    let mut out =
        Vec::with_capacity(MAGIC_GROUP_MESSAGE_V5.len() + 12 + V5_SELECTOR_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC_GROUP_MESSAGE_V5);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&selector);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_outer_v5(
    candidates: impl IntoIterator<Item = (GroupId, [u8; 32])>,
    wire: &[u8],
) -> Result<(GroupId, Vec<u8>)> {
    let magic_len = MAGIC_GROUP_MESSAGE_V5.len();
    if wire.len() < magic_len + 12 + V5_SELECTOR_LEN {
        bail!("v5 frame too short");
    }
    if &wire[..magic_len] != MAGIC_GROUP_MESSAGE_V5 {
        bail!("not a v5 group message frame");
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&wire[magic_len..magic_len + 12]);
    let wire_selector = &wire[magic_len + 12..magic_len + 12 + V5_SELECTOR_LEN];
    let ciphertext = &wire[magic_len + 12 + V5_SELECTOR_LEN..];

    // Fail-closed on selector collision, mirroring the v4 envelope's
    // `open_outer_envelope`: if a candidate's selector matches but its
    // AEAD fails, the `?` below returns immediately — later candidates
    // are NOT tried. An 8-byte cross-key collision is ~2^-64 per
    // candidate; continuing past a failed AEAD would let a genuinely
    // tampered frame masquerade as "unknown group" instead of erroring.
    for (group, group_key) in candidates {
        if v5_group_selector(&group_key, &nonce_bytes) != wire_selector {
            continue;
        }
        let outer_key = derive_outer_v5_key(&group_key);
        let cipher = ChaCha20Poly1305::new(&outer_key.into());
        let mut aad = Vec::with_capacity(magic_len + V5_SELECTOR_LEN);
        aad.extend_from_slice(MAGIC_GROUP_MESSAGE_V5);
        aad.extend_from_slice(wire_selector);
        let inner = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("outer v5 open failed (selector matched, AEAD did not)"))?;
        return Ok((group, inner));
    }
    Err(anyhow!("v5 frame: unknown group / not a member"))
}

/// Cheap dispatcher probe for the v5 magic.
pub fn is_group_message_v5_frame(wire: &[u8]) -> bool {
    wire.len() >= MAGIC_GROUP_MESSAGE_V5.len()
        && &wire[..MAGIC_GROUP_MESSAGE_V5.len()] == MAGIC_GROUP_MESSAGE_V5
}

/// Open a sealed v5 frame against the candidate set and compute its
/// [`v3_message_id`] (the id derivation is format-independent: group +
/// sender + iteration + inner ciphertext, so a v3 sender and a v5
/// receiver — or vice versa during the migration window — still agree
/// on the id an ack must carry).
pub fn extract_v5_message_id(
    candidates: impl IntoIterator<Item = (GroupId, [u8; 32])>,
    wire: &[u8],
) -> Option<[u8; 16]> {
    let (group, inner) = open_outer_v5(candidates, wire).ok()?;
    let msg: SenderKeyMessage = bounded_bincode_deserialize(&inner).ok()?;
    Some(v3_message_id(
        &group,
        &msg.sender_id,
        msg.iteration,
        &msg.payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Member {
        ks: SecureKeyStore,
        id: IdentityId,
        _dir: TempDir,
    }

    impl Member {
        fn new(tag: u8) -> Self {
            let dir = TempDir::new().unwrap();
            let ks = SecureKeyStore::new(dir.path().join("ks.db"), b"test-sender-keys").unwrap();
            Member {
                ks,
                id: IdentityId::from([tag; 32]),
                _dir: dir,
            }
        }
    }

    const GROUP_KEY: [u8; 32] = [0x42; 32];

    fn group() -> GroupId {
        GroupId::from_bytes([0xAB; 32])
    }

    /// Three members with everyone's sender keys installed everywhere.
    fn trio() -> (Member, Member, Member) {
        let mut a = Member::new(1);
        let mut b = Member::new(2);
        let mut c = Member::new(3);
        let g = group();
        let da = create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();
        let db = create_or_get_own_sender_key(&mut b.ks, &g, b.id).unwrap();
        let dc = create_or_get_own_sender_key(&mut c.ks, &g, c.id).unwrap();
        for (m, dists) in [
            (&mut a, [&db, &dc]),
            (&mut b, [&da, &dc]),
            (&mut c, [&da, &db]),
        ] {
            for d in dists {
                install_sender_key(&mut m.ks, d.sender_id, d).unwrap();
            }
        }
        (a, b, c)
    }

    #[test]
    fn v3_magic_is_pinned() {
        assert_eq!(MAGIC_GROUP_MESSAGE_V3, b"QUBEE_GMS\x03");
    }

    #[test]
    fn v3_message_id_is_stable_and_frame_derivable() {
        let (mut a, mut b, _c) = trio();
        let g = group();

        let w1 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"one").unwrap();
        let w2 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"two").unwrap();

        // Sender and receiver derive the same id from the same frame.
        let id1_send = extract_v3_message_id(&GROUP_KEY, &w1).unwrap();
        let id1_recv = extract_v3_message_id(&GROUP_KEY, &w1).unwrap();
        assert_eq!(id1_send, id1_recv);

        // Distinct messages (and iterations) get distinct ids.
        let id2 = extract_v3_message_id(&GROUP_KEY, &w2).unwrap();
        assert_ne!(id1_send, id2);

        // Bob, decrypting, derives the same id the sender would ack against.
        let _ = decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w1).unwrap();
        assert_eq!(extract_v3_message_id(&GROUP_KEY, &w1).unwrap(), id1_send);

        // Wrong group key can't open the envelope → no id.
        assert!(extract_v3_message_id(&[0u8; 32], &w1).is_none());
        // A non-v3 frame yields nothing.
        assert!(extract_v3_message_id(&GROUP_KEY, b"not a frame").is_none());
    }

    #[test]
    fn padding_collapses_small_messages_to_one_wire_size() {
        let (mut a, _b, _c) = trio();
        let g = group();
        // Two very different plaintext lengths, both under the 256 bucket.
        let short = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"hi").unwrap();
        let long =
            encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, &[0x5a; 200]).unwrap();
        assert_eq!(
            short.len(),
            long.len(),
            "distinct small message lengths must share one on-wire size",
        );
    }

    #[test]
    fn own_chain_iteration_tracks_lifecycle() {
        let mut a = Member::new(9);
        let g = group();
        assert_eq!(own_chain_iteration(&mut a.ks, &g).unwrap(), None);

        create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();
        assert_eq!(own_chain_iteration(&mut a.ks, &g).unwrap(), Some(0));

        encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"x").unwrap();
        assert_eq!(own_chain_iteration(&mut a.ks, &g).unwrap(), Some(1));

        reset_group_sender_state(&mut a.ks, &g).unwrap();
        assert_eq!(own_chain_iteration(&mut a.ks, &g).unwrap(), None);
    }

    #[test]
    fn all_members_decrypt_everyone_elses_messages() {
        let (mut a, mut b, mut c) = trio();
        let g = group();

        let wa =
            encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"from alice").unwrap();
        assert!(is_group_message_v3_frame(&wa));
        for m in [&mut b, &mut c] {
            let (gid, sender, pt) = decrypt_sender_key_message(&mut m.ks, &GROUP_KEY, &wa).unwrap();
            assert_eq!(
                (gid, sender, pt.as_slice()),
                (g, a.id, b"from alice".as_slice())
            );
        }

        let wb = encrypt_sender_key_message(&mut b.ks, &g, &GROUP_KEY, b.id, b"from bob").unwrap();
        let (_, sender, pt) = decrypt_sender_key_message(&mut a.ks, &GROUP_KEY, &wb).unwrap();
        assert_eq!((sender, pt.as_slice()), (b.id, b"from bob".as_slice()));
    }

    #[test]
    fn out_of_order_delivery_and_replay_rejection() {
        let (mut a, mut b, _c) = trio();
        let g = group();

        let w0 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"msg 0").unwrap();
        let w1 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"msg 1").unwrap();
        let w2 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"msg 2").unwrap();

        // Deliver 2 first (skipping 0 and 1), then 0, then 1.
        assert_eq!(
            decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w2)
                .unwrap()
                .2,
            b"msg 2"
        );
        assert_eq!(
            decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w0)
                .unwrap()
                .2,
            b"msg 0"
        );
        assert_eq!(
            decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w1)
                .unwrap()
                .2,
            b"msg 1"
        );

        // Every frame's key is now consumed.
        for w in [&w0, &w1, &w2] {
            let err = decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, w).unwrap_err();
            assert!(err.to_string().contains("consumed"), "{err}");
        }
    }

    #[test]
    fn member_cannot_forge_another_members_message() {
        let (mut a, mut b, mut c) = trio();
        let g = group();

        // Bob knows Alice's chain key (every member does) and forges a
        // frame at her next iteration — but he can't sign with her
        // ephemeral key, so Carol must reject it.
        let alice_state = load_recv_state(&mut b.ks, &g, &a.id).unwrap().unwrap();
        let iteration = alice_state.iteration;
        let (_, mut mk) = kdf_chain(&alice_state.chain_key);
        let (key, nonce) = derive_msg_aead(&mk).unwrap();
        mk.zeroize();
        let cipher = ChaCha20Poly1305::new(&key.into());
        let payload = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: b"i am totally alice".as_slice(),
                    aad: &inner_aad(&g, &a.id, iteration),
                },
            )
            .unwrap();
        let bob_signing = {
            let own = load_own_state(&mut b.ks, &g).unwrap().unwrap();
            SigningKey::from_bytes(&own.signing_secret)
        };
        let signature = bob_signing.sign(&signature_digest(&g, &a.id, iteration, &payload));
        let inner = bincode::serialize(&SenderKeyMessage {
            sender_id: a.id,
            iteration,
            payload,
            signature: signature.to_bytes().to_vec(),
        })
        .unwrap();
        let forged = seal_outer_v3(&g, &GROUP_KEY, &inner).unwrap();

        let err = decrypt_sender_key_message(&mut c.ks, &GROUP_KEY, &forged).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");

        // Alice's genuine next message still decrypts for Carol.
        let w = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"genuine").unwrap();
        assert_eq!(
            decrypt_sender_key_message(&mut c.ks, &GROUP_KEY, &w)
                .unwrap()
                .2,
            b"genuine"
        );
    }

    #[test]
    fn unknown_sender_and_wrong_group_key_fail() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let mut outsider = Member::new(9);

        let w = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"hi").unwrap();
        // Outsider has the frame + the group key but no distribution.
        let err = decrypt_sender_key_message(&mut outsider.ks, &GROUP_KEY, &w).unwrap_err();
        assert!(err.to_string().contains("no sender key installed"), "{err}");

        // Member with a rotated/wrong group key can't even open the
        // outer envelope.
        let err = decrypt_sender_key_message(&mut b.ks, &[0x99; 32], &w).unwrap_err();
        assert!(err.to_string().contains("outer"), "{err}");
    }

    #[test]
    fn distribution_must_match_authenticated_channel_sender() {
        let mut a = Member::new(1);
        let mut m = Member::new(7);
        let g = group();
        let mut dist = create_or_get_own_sender_key(&mut m.ks, &g, m.id).unwrap();
        // Mallory relabels her distribution as Alice's.
        dist.sender_id = a.id;
        let err = install_sender_key(&mut a.ks, m.id, &dist).unwrap_err();
        assert!(err.to_string().contains("different sender"), "{err}");
    }

    #[test]
    fn stale_redistribution_cannot_roll_chain_back() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let original = create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();

        let w = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"advance").unwrap();
        decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w).unwrap();

        // Replaying the iteration-0 distribution must not reset Bob's
        // receive chain (which would let the consumed key re-derive).
        let err = install_sender_key(&mut b.ks, a.id, &original).unwrap_err();
        assert!(err.to_string().contains("stale"), "{err}");
        assert!(decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w).is_err());
    }

    #[test]
    fn rekey_with_fresh_chain_is_accepted() {
        let (mut a, mut b, _c) = trio();
        let g = group();

        let w_old = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"old").unwrap();
        decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w_old).unwrap();

        // Membership change: Alice resets and redistributes.
        assert!(reset_group_sender_state(&mut a.ks, &g).unwrap() >= 1);
        let fresh = create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();
        assert_eq!(fresh.iteration, 0);
        install_sender_key(&mut b.ks, a.id, &fresh).unwrap();

        let w_new =
            encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"new chain").unwrap();
        assert_eq!(
            decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w_new)
                .unwrap()
                .2,
            b"new chain"
        );
    }

    #[test]
    fn reset_wipes_own_and_peer_state_for_that_group_only() {
        let (mut a, _b, _c) = trio();
        let g = group();
        let other = GroupId::from_bytes([0xCD; 32]);
        create_or_get_own_sender_key(&mut a.ks, &other, a.id).unwrap();

        // Own chain for `g` + two installed peers = 3 states.
        assert_eq!(reset_group_sender_state(&mut a.ks, &g).unwrap(), 3);
        assert_eq!(reset_group_sender_state(&mut a.ks, &g).unwrap(), 0);
        // The other group's chain survives.
        assert!(load_own_state(&mut a.ks, &other).unwrap().is_some());
    }

    #[test]
    fn skip_beyond_window_is_rejected() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let mut last = Vec::new();
        // The frame at iteration MAX_SKIP+1 exceeds the window for a
        // receiver still at iteration 0.
        for _ in 0..=(SENDER_MAX_SKIP + 1) {
            last = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"x").unwrap();
        }
        let err = decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &last).unwrap_err();
        assert!(err.to_string().contains("skip too large"), "{err}");
    }

    #[test]
    fn distribution_round_trips_and_is_bounded() {
        let mut a = Member::new(1);
        let g = group();
        let d = create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();
        let bytes = d.to_bytes().unwrap();
        assert_eq!(SenderKeyDistribution::from_bytes(&bytes).unwrap(), d);
        assert!(SenderKeyDistribution::from_bytes(b"garbage").is_err());
    }

    #[test]
    fn own_chain_persists_across_reload() {
        let mut a = Member::new(1);
        let g = group();
        let d1 = create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();
        let d2 = create_or_get_own_sender_key(&mut a.ks, &g, a.id).unwrap();
        assert_eq!(d1, d2, "second call must reload, not regenerate");
    }

    #[test]
    fn v5_magic_is_pinned() {
        assert_eq!(MAGIC_GROUP_MESSAGE_V5, b"QUBEE_GMS\x05");
    }

    #[test]
    fn v5_selector_is_pinned() {
        // Golden vector: a silent change to the selector KDF context,
        // hash, or truncation strands every deployed receiver (their
        // trial-match never hits). Fixed key + nonce, pinned output.
        let selector = v5_group_selector(&[0x11; 32], &[0x22; 12]);
        assert_eq!(selector, [0xa0, 0xc8, 0xbf, 0x13, 0x10, 0x0b, 0x4d, 0xb4]);
    }

    #[test]
    fn v5_round_trips_across_members() {
        let (mut a, mut b, mut c) = trio();
        let g = group();
        let wire =
            encrypt_sender_key_message_v5(&mut a.ks, &g, &GROUP_KEY, a.id, b"hi v5").unwrap();
        assert!(is_group_message_v5_frame(&wire));
        assert!(!is_group_message_v3_frame(&wire));
        // No plaintext group id anywhere on the wire.
        assert!(
            !wire.windows(32).any(|w| w == g.as_bytes()),
            "v5 wire must not contain the group id in the clear",
        );
        for m in [&mut b, &mut c] {
            let (gid, sender, pt) =
                decrypt_sender_key_message_v5(&mut m.ks, vec![(g, GROUP_KEY)], &wire).unwrap();
            assert_eq!(gid, g);
            assert_eq!(sender, a.id);
            assert_eq!(pt, b"hi v5");
        }
    }

    #[test]
    fn v5_trial_match_picks_the_right_group_among_many() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let wire =
            encrypt_sender_key_message_v5(&mut a.ks, &g, &GROUP_KEY, a.id, b"pick me").unwrap();
        // Receiver holds several groups; only the right (id, key) pair
        // may open the frame, regardless of candidate order.
        let candidates = vec![
            (GroupId::from_bytes([0x01; 32]), [0x01; 32]),
            (GroupId::from_bytes([0x02; 32]), [0x02; 32]),
            (g, GROUP_KEY),
            (GroupId::from_bytes([0x03; 32]), [0x03; 32]),
        ];
        let (gid, _, pt) = decrypt_sender_key_message_v5(&mut b.ks, candidates, &wire).unwrap();
        assert_eq!(gid, g);
        assert_eq!(pt, b"pick me");
    }

    #[test]
    fn v5_rejected_without_the_group_key() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let wire =
            encrypt_sender_key_message_v5(&mut a.ks, &g, &GROUP_KEY, a.id, b"secret").unwrap();
        let wrong = vec![
            (g, [0x99; 32]),
            (GroupId::from_bytes([0x77; 32]), [0x77; 32]),
        ];
        assert!(decrypt_sender_key_message_v5(&mut b.ks, wrong, &wire).is_err());
    }

    #[test]
    fn v5_tamper_is_rejected() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let wire = encrypt_sender_key_message_v5(&mut a.ks, &g, &GROUP_KEY, a.id, b"seal").unwrap();
        let last = wire.len() - 1;
        for flip_at in [
            MAGIC_GROUP_MESSAGE_V5.len(),
            MAGIC_GROUP_MESSAGE_V5.len() + 12,
            last,
        ] {
            let mut bad = wire.clone();
            bad[flip_at] ^= 0x01;
            assert!(
                decrypt_sender_key_message_v5(&mut b.ks, vec![(g, GROUP_KEY)], &bad).is_err(),
                "flipping byte {flip_at} must not decrypt",
            );
        }
    }

    #[test]
    fn v5_and_v3_ids_are_derived_by_the_same_rule_per_chain_position() {
        // The migration window has mixed senders, so both formats feed
        // the same id derivation (`v3_message_id` over group + sender +
        // iteration + inner ciphertext — the outer envelope never
        // contributes). Consecutive sends occupy distinct chain
        // positions and therefore must yield distinct ids.
        let (mut a, mut b, _c) = trio();
        let g = group();
        let w3 = encrypt_sender_key_message(&mut a.ks, &g, &GROUP_KEY, a.id, b"same").unwrap();
        let id3 = extract_v3_message_id(&GROUP_KEY, &w3).unwrap();
        let (_, sender, _) = decrypt_sender_key_message(&mut b.ks, &GROUP_KEY, &w3).unwrap();
        assert_eq!(sender, a.id);

        let w5 = encrypt_sender_key_message_v5(&mut a.ks, &g, &GROUP_KEY, a.id, b"same").unwrap();
        let id5 = extract_v5_message_id(vec![(g, GROUP_KEY)], &w5).unwrap();
        assert_ne!(
            id3, id5,
            "different chain positions must give different ids"
        );
        let (gid, _, pt) =
            decrypt_sender_key_message_v5(&mut b.ks, vec![(g, GROUP_KEY)], &w5).unwrap();
        assert_eq!(gid, g);
        assert_eq!(pt, b"same");
    }

    #[test]
    fn v5_replay_is_rejected_by_consumed_message_key() {
        let (mut a, mut b, _c) = trio();
        let g = group();
        let wire = encrypt_sender_key_message_v5(&mut a.ks, &g, &GROUP_KEY, a.id, b"once").unwrap();
        decrypt_sender_key_message_v5(&mut b.ks, vec![(g, GROUP_KEY)], &wire).unwrap();
        assert!(
            decrypt_sender_key_message_v5(&mut b.ks, vec![(g, GROUP_KEY)], &wire).is_err(),
            "replaying the same v5 frame must fail (message key consumed)",
        );
    }
}
