//! Live 1:1 send/receive orchestration (Ratchet Stage 3d).
//!
//! Glues the Stage 3 pieces into the two operations the JNI layer
//! exposes: encrypt-to-peer and decrypt-from-peer, both stateless from
//! the caller's perspective — all session state lives in the encrypted
//! keystore.
//!
//! ## State-safety rules
//!
//! * Session state is persisted **only after a successful operation**.
//!   A failed decrypt mutates only an in-memory copy that is then
//!   dropped, so garbage or replayed frames can never advance (or
//!   corrupt) the stored ratchet.
//! * Replays are rejected by the ratchet itself: a message key is
//!   consumed on first decrypt, so the same frame never opens twice
//!   against persisted state.
//!
//! ## Handshake-completion rules
//!
//! * The initiator attaches its PQXDH `InitialMessage` to **every**
//!   outgoing frame until it first successfully decrypts a reply — the
//!   responder may have missed any prefix of the stream.
//! * The responder only establishes a session from an initial whose
//!   X25519 identity matches the claimed sender's **cached, verified
//!   prekey bundle** (installed via [`install_peer_bundle`]). No cached
//!   bundle ⇒ fail closed. This is what stops a third party (bundles
//!   are public) from opening a session under someone else's id: without
//!   the bundle owner's X25519 identity *secret* they cannot derive the
//!   same PQXDH secret we do, so their frames never decrypt.
//! * Each accepted initial's hash is recorded; re-establishing from the
//!   same initial is refused (an attacker replaying the conversation's
//!   first frame must not roll the session back).
//!
//! ## Simultaneous-open race
//!
//! If both parties initiate before either receives, the party whose
//! identity id is byte-wise **smaller** wins the initiator role: the
//! larger-id party discards its initiator session when the winner's
//! initial arrives, and its own in-flight initial frames are dropped by
//! the winner. The loser's first sends are lost (the app layer's
//! retry/resend handles that), after which the surviving session carries
//! both directions. Same trade-off Signal makes for session racing.

use anyhow::{anyhow, bail, Result};

use crate::groups::group_handshake::{verify_prekey_bundle, GroupHandshake};
use crate::identity::identity_key::IdentityId;
use crate::ratchet::direct_message::DirectMessage;
use crate::ratchet::pqxdh::WireInitialMessage;
use crate::ratchet::prekey_store::{
    body_to_public, get_or_create_local_bundle, get_peer_bundle, store_peer_bundle,
};
use crate::ratchet::sender_keys::SenderKeyDistribution;
use crate::ratchet::session::{load_session, store_session, Session};
use crate::storage::secure_keystore::{KeyMetadata, KeyType, KeyUsage, SecureKeyStore};

fn pending_initial_key(peer: &IdentityId) -> String {
    format!("ratchet_pending_initial_{}", hex::encode(peer.as_ref()))
}

fn accepted_initial_key(peer: &IdentityId) -> String {
    format!("ratchet_accepted_initial_{}", hex::encode(peer.as_ref()))
}

fn marker_metadata() -> KeyMetadata {
    KeyMetadata {
        algorithm: "ratchet-direct-marker".to_string(),
        key_size: 32,
        usage: vec![KeyUsage::KeyAgreement],
        expiry: None,
        tags: std::collections::HashMap::new(),
    }
}

fn initial_hash(initial: &WireInitialMessage) -> Result<[u8; 32]> {
    let bytes =
        bincode::serialize(initial).map_err(|e| anyhow!("serialize initial for hash: {e}"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Verify + cache a peer's signed prekey bundle frame (the
/// `GroupHandshake::PrekeyBundle` wire bytes produced by
/// `nativeBuildLocalPrekeyBundle` on their device). Returns the
/// publisher's identity id on success. This is the trust root for the
/// responder-side identity binding — only install bundles received over
/// an authenticated channel (group membership, onboarding link).
pub fn install_peer_bundle(ks: &mut SecureKeyStore, wire: &[u8]) -> Result<IdentityId> {
    let frame =
        GroupHandshake::from_wire(wire).ok_or_else(|| anyhow!("not a handshake wire frame"))?;
    let (body, signature) = match frame {
        GroupHandshake::PrekeyBundle { body, signature } => (body, signature),
        _ => bail!("not a prekey bundle frame"),
    };
    if !verify_prekey_bundle(&body, &signature)? {
        bail!("prekey bundle signature verification failed");
    }
    let id = body.publisher.identity_id;
    store_peer_bundle(ks, &body)?;
    Ok(id)
}

/// Encrypt `plaintext` for `peer_id`, establishing a session on first
/// use from the peer's cached prekey bundle. Returns the
/// `QUBEE_DMS\x01` wire frame. Fails if no session exists and no bundle
/// for the peer has been installed.
pub fn encrypt_direct(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    plaintext: &[u8],
    now: u64,
) -> Result<Vec<u8>> {
    let mut session = match load_session(ks, &peer_id)? {
        Some(s) => s,
        None => {
            let body = get_peer_bundle(ks, &peer_id)?
                .ok_or_else(|| anyhow!("no prekey bundle installed for peer"))?;
            let peer_public = body_to_public(&body)?;
            let (local_secret, _kem) = get_or_create_local_bundle(ks, now)?;
            let (session, initial) =
                Session::establish_initiator(local_id, peer_id, &local_secret, &peer_public)?;
            let wire_initial = WireInitialMessage::from_message(&initial);
            let bytes = bincode::serialize(&wire_initial)
                .map_err(|e| anyhow!("serialize pending initial: {e}"))?;
            ks.store_key(
                &pending_initial_key(&peer_id),
                &bytes,
                KeyType::EphemeralKey,
                marker_metadata(),
            )?;
            session
        }
    };

    let initial = match ks.retrieve_key(&pending_initial_key(&peer_id))? {
        Some(secret) => Some(
            bincode::deserialize::<WireInitialMessage>(secrecy::ExposeSecret::expose_secret(
                &secret,
            ))
            .map_err(|e| anyhow!("decode pending initial: {e}"))?,
        ),
        None => None,
    };

    let (header, ciphertext) = session.encrypt(plaintext)?;
    store_session(ks, &session)?;
    DirectMessage {
        sender_id: local_id,
        initial,
        header,
        ciphertext,
    }
    .to_wire()
}

/// Decrypt an inbound `QUBEE_DMS\x01` frame, establishing the responder
/// side of the session on the conversation's first message. Returns the
/// sender's identity id and the plaintext.
pub fn decrypt_direct(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, Vec<u8>)> {
    let dm = DirectMessage::from_wire(wire).ok_or_else(|| anyhow!("not a direct message frame"))?;
    let peer_id = dm.sender_id;
    if peer_id == local_id {
        bail!("direct message claims to be from ourselves");
    }

    if let Some(mut session) = load_session(ks, &peer_id)? {
        match session.decrypt(&dm.header, &dm.ciphertext) {
            Ok(plaintext) => {
                store_session(ks, &session)?;
                // Receiving on this session proves the peer holds it too:
                // stop attaching our own initial (if we were initiator).
                ks.delete_key(&pending_initial_key(&peer_id))?;
                return Ok((peer_id, plaintext));
            }
            Err(e) => {
                // Simultaneous-open: yield our initiator session only to
                // a byte-wise-smaller peer carrying a fresh initial.
                let peer_wins = peer_id.as_ref() < local_id.as_ref();
                if dm.initial.is_none() || !peer_wins {
                    return Err(e);
                }
            }
        }
    }

    let initial = dm
        .initial
        .as_ref()
        .ok_or_else(|| anyhow!("no session with sender and frame carries no initial"))?;

    let hash = initial_hash(initial)?;
    if let Some(prev) = ks.retrieve_key(&accepted_initial_key(&peer_id))? {
        if secrecy::ExposeSecret::expose_secret(&prev).as_slice() == hash.as_slice() {
            bail!("initial message already consumed (replay)");
        }
    }

    let bundle = get_peer_bundle(ks, &peer_id)?
        .ok_or_else(|| anyhow!("no verified prekey bundle for claimed sender"))?;
    if initial.identity != bundle.identity_x25519 {
        bail!("initial message identity key does not match sender's verified bundle");
    }

    let (local_secret, _kem) = get_or_create_local_bundle(ks, now)?;
    let mut session =
        Session::establish_responder(local_id, peer_id, &local_secret, &initial.to_message()?)?;
    let plaintext = session.decrypt(&dm.header, &dm.ciphertext)?;
    store_session(ks, &session)?;
    ks.store_key(
        &accepted_initial_key(&peer_id),
        &hash,
        KeyType::EphemeralKey,
        marker_metadata(),
    )?;
    Ok((peer_id, plaintext))
}

/// Cheap sender extraction for dispatcher routing — parses the frame
/// without touching any session state. `None` if `wire` is not a direct
/// message frame.
pub fn inspect_direct_sender(wire: &[u8]) -> Option<IdentityId> {
    DirectMessage::from_wire(wire).map(|dm| dm.sender_id)
}

/// Tear down the 1:1 session with a peer: the session itself, our
/// pending outgoing initial, and the accepted-initial replay marker.
/// Returns how many keystore entries were removed (0 = nothing existed).
///
/// This is the recovery path for a peer who wiped their device and
/// re-initiated but loses the simultaneous-open tie-break: their fresh
/// initial is refused while we still hold the old session, so the app
/// layer (on user action or a trust-state event) resets and lets the
/// next inbound initial re-establish. Resetting mid-conversation only
/// costs in-flight messages — the next exchange re-handshakes — but
/// don't call it casually: an attacker who can trick the app into
/// resetting gains nothing cryptographically (establishment still
/// requires the peer's verified bundle identity), it's purely a
/// liveness lever.
pub fn reset_direct_session(ks: &mut SecureKeyStore, peer: &IdentityId) -> Result<usize> {
    let mut deleted = 0;
    for key in [
        crate::ratchet::session::session_key_id(peer),
        pending_initial_key(peer),
        accepted_initial_key(peer),
    ] {
        if ks.delete_key(&key)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// Tagged payloads (Stage 5 cutover plumbing)
// ---------------------------------------------------------------------------
//
// The 1:1 channel carries more than chat text: sender-key
// distributions for the v3 group format ride it too (it is the only
// channel confidential enough for them). A one-byte tag in front of
// the ratchet plaintext distinguishes the kinds. The tag sits *inside*
// the encryption, so it leaks nothing on the wire; it is still a
// compatibility surface between app versions, so the tag values are
// pinned in `tests/wire_stability.rs` like any other format byte.

pub const PAYLOAD_TAG_TEXT: u8 = 0x01;
pub const PAYLOAD_TAG_SENDER_KEY_DIST: u8 = 0x02;

/// A decoded 1:1 plaintext.
#[derive(Debug, PartialEq, Eq)]
pub enum DirectPayload {
    /// A chat message.
    Text(String),
    /// A sender-key distribution for a group the peer shares with us.
    /// The caller must pass the *channel-authenticated* sender id to
    /// [`crate::ratchet::sender_keys::install_sender_key`] — never the
    /// distribution's own claim.
    SenderKeyDistribution(SenderKeyDistribution),
}

fn encode_payload(payload: &DirectPayload) -> Result<Vec<u8>> {
    match payload {
        DirectPayload::Text(text) => {
            let mut out = Vec::with_capacity(1 + text.len());
            out.push(PAYLOAD_TAG_TEXT);
            out.extend_from_slice(text.as_bytes());
            Ok(out)
        }
        DirectPayload::SenderKeyDistribution(dist) => {
            let body = dist.to_bytes()?;
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(PAYLOAD_TAG_SENDER_KEY_DIST);
            out.extend_from_slice(&body);
            Ok(out)
        }
    }
}

fn decode_payload(bytes: &[u8]) -> Result<DirectPayload> {
    let (tag, body) = bytes
        .split_first()
        .ok_or_else(|| anyhow!("empty direct payload"))?;
    match *tag {
        PAYLOAD_TAG_TEXT => Ok(DirectPayload::Text(
            String::from_utf8(body.to_vec()).map_err(|e| anyhow!("text payload not UTF-8: {e}"))?,
        )),
        PAYLOAD_TAG_SENDER_KEY_DIST => Ok(DirectPayload::SenderKeyDistribution(
            SenderKeyDistribution::from_bytes(body)?,
        )),
        other => bail!("unknown direct payload tag {other:#04x}"),
    }
}

/// Encrypt a chat text for `peer_id` (tagged-payload flavour of
/// [`encrypt_direct`] — what the JNI send path uses).
pub fn encrypt_direct_text(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    text: &str,
    now: u64,
) -> Result<Vec<u8>> {
    let payload = encode_payload(&DirectPayload::Text(text.to_string()))?;
    encrypt_direct(ks, local_id, peer_id, &payload, now)
}

/// Encrypt a sender-key distribution for `peer_id`. The confidential
/// transport for Stage 4 group rekeys — one call per member.
pub fn encrypt_direct_distribution(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    peer_id: IdentityId,
    dist: &SenderKeyDistribution,
    now: u64,
) -> Result<Vec<u8>> {
    let payload = encode_payload(&DirectPayload::SenderKeyDistribution(dist.clone()))?;
    encrypt_direct(ks, local_id, peer_id, &payload, now)
}

/// Decrypt an inbound frame and decode its tagged payload. Returns the
/// channel-authenticated sender and the payload kind.
pub fn decrypt_direct_payload(
    ks: &mut SecureKeyStore,
    local_id: IdentityId,
    wire: &[u8],
    now: u64,
) -> Result<(IdentityId, DirectPayload)> {
    let (sender, plaintext) = decrypt_direct(ks, local_id, wire, now)?;
    Ok((sender, decode_payload(&plaintext)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::group_handshake::sign_prekey_bundle;
    use crate::identity::identity_key::IdentityKeyPair;
    use crate::ratchet::prekey_store::build_body;
    use tempfile::TempDir;

    struct Device {
        ks: SecureKeyStore,
        kp: IdentityKeyPair,
        _dir: TempDir,
    }

    impl Device {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let ks = SecureKeyStore::new(dir.path().join("ks.db"), b"test-direct").unwrap();
            Device {
                ks,
                kp: IdentityKeyPair::generate().unwrap(),
                _dir: dir,
            }
        }

        fn signed_bundle_wire(&mut self) -> Vec<u8> {
            let (secret, kem_pub) = get_or_create_local_bundle(&mut self.ks, 1).unwrap();
            let body = build_body(&secret, &kem_pub, self.kp.public_key(), 1);
            sign_prekey_bundle(&self.kp, body)
                .unwrap()
                .to_wire()
                .unwrap()
        }
    }

    /// Two devices with each other's verified bundles installed.
    fn paired() -> (Device, Device) {
        let mut a = Device::new();
        let mut b = Device::new();
        let (aw, bw) = (a.signed_bundle_wire(), b.signed_bundle_wire());
        assert_eq!(
            install_peer_bundle(&mut a.ks, &bw).unwrap(),
            b.kp.identity_id()
        );
        assert_eq!(
            install_peer_bundle(&mut b.ks, &aw).unwrap(),
            a.kp.identity_id()
        );
        (a, b)
    }

    #[test]
    fn full_conversation_both_ways() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());

        let w1 = encrypt_direct(&mut a.ks, aid, bid, b"hello bob", 10).unwrap();
        assert_eq!(inspect_direct_sender(&w1).unwrap(), aid);
        let (from, pt) = decrypt_direct(&mut b.ks, bid, &w1, 10).unwrap();
        assert_eq!((from, pt.as_slice()), (aid, b"hello bob".as_slice()));

        let w2 = encrypt_direct(&mut b.ks, bid, aid, b"hello alice", 11).unwrap();
        let (from, pt) = decrypt_direct(&mut a.ks, aid, &w2, 11).unwrap();
        assert_eq!((from, pt.as_slice()), (bid, b"hello alice".as_slice()));

        for i in 0..5u8 {
            let w = encrypt_direct(&mut a.ks, aid, bid, &[i], 12).unwrap();
            assert_eq!(decrypt_direct(&mut b.ks, bid, &w, 12).unwrap().1, [i]);
        }
    }

    #[test]
    fn initial_rides_every_frame_until_first_reply() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());

        let w1 = encrypt_direct(&mut a.ks, aid, bid, b"one", 1).unwrap();
        let w2 = encrypt_direct(&mut a.ks, aid, bid, b"two", 1).unwrap();
        assert!(DirectMessage::from_wire(&w1).unwrap().initial.is_some());
        assert!(DirectMessage::from_wire(&w2).unwrap().initial.is_some());

        // Bob misses w1 entirely; w2 alone must still establish (via its
        // attached initial + the ratchet's skipped-key handling).
        let (_, pt) = decrypt_direct(&mut b.ks, bid, &w2, 1).unwrap();
        assert_eq!(pt, b"two");

        // After Alice hears back, her frames stop carrying the initial.
        let wb = encrypt_direct(&mut b.ks, bid, aid, b"ack", 2).unwrap();
        decrypt_direct(&mut a.ks, aid, &wb, 2).unwrap();
        let w3 = encrypt_direct(&mut a.ks, aid, bid, b"three", 3).unwrap();
        assert!(DirectMessage::from_wire(&w3).unwrap().initial.is_none());
        assert_eq!(decrypt_direct(&mut b.ks, bid, &w3, 3).unwrap().1, b"three");
    }

    #[test]
    fn replayed_frame_is_rejected_and_state_survives() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());

        let w1 = encrypt_direct(&mut a.ks, aid, bid, b"first", 1).unwrap();
        decrypt_direct(&mut b.ks, bid, &w1, 1).unwrap();
        // Replaying the very first frame (which carries the initial) must
        // not decrypt again, roll the session back, or corrupt state.
        assert!(decrypt_direct(&mut b.ks, bid, &w1, 1).is_err());

        let w2 = encrypt_direct(&mut a.ks, aid, bid, b"second", 2).unwrap();
        assert_eq!(decrypt_direct(&mut b.ks, bid, &w2, 2).unwrap().1, b"second");
        assert!(decrypt_direct(&mut b.ks, bid, &w2, 2).is_err());

        let w3 = encrypt_direct(&mut a.ks, aid, bid, b"third", 3).unwrap();
        assert_eq!(decrypt_direct(&mut b.ks, bid, &w3, 3).unwrap().1, b"third");
    }

    #[test]
    fn encrypt_without_installed_bundle_fails_closed() {
        let mut a = Device::new();
        let b = Device::new();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        assert!(encrypt_direct(&mut a.ks, aid, bid, b"x", 1).is_err());
    }

    #[test]
    fn responder_without_senders_bundle_fails_closed() {
        // Bob never installed Alice's bundle → no identity binding
        // possible → the frame is rejected even though it is genuine.
        let mut a = Device::new();
        let mut b = Device::new();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        let bw = b.signed_bundle_wire();
        install_peer_bundle(&mut a.ks, &bw).unwrap();

        let w = encrypt_direct(&mut a.ks, aid, bid, b"hi", 1).unwrap();
        let err = decrypt_direct(&mut b.ks, bid, &w, 1).unwrap_err();
        assert!(err.to_string().contains("no verified prekey bundle"));
    }

    #[test]
    fn attacker_cannot_open_session_under_peers_id() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        let mut mallory = Device::new();
        let mid = mallory.kp.identity_id();

        // Mallory crafts a genuine PQXDH initiate against Bob's public
        // bundle but claims Alice's sender_id. The identity in her
        // initial can't match Alice's verified bundle (she doesn't hold
        // Alice's X25519 identity secret), so Bob rejects it.
        let bw = b.signed_bundle_wire();
        install_peer_bundle(&mut mallory.ks, &bw).unwrap();
        let forged = {
            let wire = encrypt_direct(&mut mallory.ks, mid, bid, b"evil", 1).unwrap();
            let mut dm = DirectMessage::from_wire(&wire).unwrap();
            dm.sender_id = aid;
            dm.to_wire().unwrap()
        };
        let err = decrypt_direct(&mut b.ks, bid, &forged, 1).unwrap_err();
        assert!(err.to_string().contains("does not match"));

        // The genuine conversation still works afterwards.
        let w = encrypt_direct(&mut a.ks, aid, bid, b"real", 2).unwrap();
        assert_eq!(decrypt_direct(&mut b.ks, bid, &w, 2).unwrap().1, b"real");
    }

    #[test]
    fn simultaneous_open_converges_on_smaller_id_initiator() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        // Both initiate before either receives.
        let wa = encrypt_direct(&mut a.ks, aid, bid, b"from a", 1).unwrap();
        let wb = encrypt_direct(&mut b.ks, bid, aid, b"from b", 1).unwrap();

        let winner_is_a = aid.as_ref() < bid.as_ref();
        if winner_is_a {
            // B yields to A's initial; A drops B's in-flight frame.
            assert_eq!(decrypt_direct(&mut b.ks, bid, &wa, 1).unwrap().1, b"from a");
            assert!(decrypt_direct(&mut a.ks, aid, &wb, 1).is_err());
        } else {
            assert_eq!(decrypt_direct(&mut a.ks, aid, &wb, 1).unwrap().1, b"from b");
            assert!(decrypt_direct(&mut b.ks, bid, &wa, 1).is_err());
        }

        // Either way the surviving session carries traffic both ways.
        let w1 = encrypt_direct(&mut a.ks, aid, bid, b"converged a to b", 2).unwrap();
        assert_eq!(
            decrypt_direct(&mut b.ks, bid, &w1, 2).unwrap().1,
            b"converged a to b"
        );
        let w2 = encrypt_direct(&mut b.ks, bid, aid, b"converged b to a", 3).unwrap();
        assert_eq!(
            decrypt_direct(&mut a.ks, aid, &w2, 3).unwrap().1,
            b"converged b to a"
        );
    }

    #[test]
    fn tampered_bundle_is_not_installed() {
        let mut a = Device::new();
        let mut b = Device::new();
        let mut bw = b.signed_bundle_wire();
        let n = bw.len();
        bw[n / 2] ^= 0x01;
        assert!(install_peer_bundle(&mut a.ks, &bw).is_err());
    }

    #[test]
    fn frame_claiming_to_be_from_self_is_rejected() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        let w = encrypt_direct(&mut a.ks, aid, bid, b"x", 1).unwrap();
        let mut dm = DirectMessage::from_wire(&w).unwrap();
        dm.sender_id = bid;
        let err = decrypt_direct(&mut b.ks, bid, &dm.to_wire().unwrap(), 1).unwrap_err();
        assert!(err.to_string().contains("from ourselves"));
    }

    #[test]
    fn non_direct_frames_are_not_dispatched() {
        assert!(inspect_direct_sender(b"QUBEE_GMS\x01whatever").is_none());
        assert!(inspect_direct_sender(&[]).is_none());
    }

    #[test]
    fn payload_tags_are_pinned() {
        assert_eq!(PAYLOAD_TAG_TEXT, 0x01);
        assert_eq!(PAYLOAD_TAG_SENDER_KEY_DIST, 0x02);
    }

    #[test]
    fn text_payload_round_trips_over_the_channel() {
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());

        let w = encrypt_direct_text(&mut a.ks, aid, bid, "tagged hello", 1).unwrap();
        let (sender, payload) = decrypt_direct_payload(&mut b.ks, bid, &w, 1).unwrap();
        assert_eq!(sender, aid);
        assert_eq!(payload, DirectPayload::Text("tagged hello".to_string()));
    }

    #[test]
    fn unknown_and_empty_payload_tags_are_rejected() {
        assert!(decode_payload(&[]).is_err());
        assert!(decode_payload(&[0x7F, 1, 2, 3]).is_err());
    }

    #[test]
    fn reset_unbricks_a_reinstalled_peer_that_loses_the_tiebreak() {
        let (a, b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());

        // The peer with the byte-wise LARGER id loses the tie-break —
        // make that the one who wipes, so the brick actually occurs.
        let (mut survivor, mut wiped) = if aid.as_ref() < bid.as_ref() {
            (a, b)
        } else {
            (b, a)
        };
        let (sid, wid) = (survivor.kp.identity_id(), wiped.kp.identity_id());

        // Established conversation.
        let w = encrypt_direct(&mut survivor.ks, sid, wid, b"hello", 1).unwrap();
        decrypt_direct(&mut wiped.ks, wid, &w, 1).unwrap();
        let w = encrypt_direct(&mut wiped.ks, wid, sid, b"ack", 1).unwrap();
        decrypt_direct(&mut survivor.ks, sid, &w, 1).unwrap();

        // Device wipe with identity restored from backup: same keypair,
        // empty keystore (sessions + prekey secrets gone).
        let dir = TempDir::new().unwrap();
        wiped.ks = SecureKeyStore::new(dir.path().join("ks2.db"), b"test-direct").unwrap();
        wiped._dir = dir;

        // Fresh bundles exchanged both ways (the wiped device generated
        // new prekeys; the survivor's cache entry is overwritten).
        let new_bundle = wiped.signed_bundle_wire();
        install_peer_bundle(&mut survivor.ks, &new_bundle).unwrap();
        let survivor_bundle = survivor.signed_bundle_wire();
        install_peer_bundle(&mut wiped.ks, &survivor_bundle).unwrap();

        // The wiped device re-initiates — and is bricked: the survivor
        // still holds the old session, and the wiped peer loses the
        // tie-break, so its fresh initial is refused.
        let w1 = encrypt_direct(&mut wiped.ks, wid, sid, b"i am back", 2).unwrap();
        assert!(decrypt_direct(&mut survivor.ks, sid, &w1, 2).is_err());

        // Recovery: the survivor resets the session (user action /
        // trust-state event), after which the same frame establishes
        // through the fresh initial and decrypts.
        assert!(reset_direct_session(&mut survivor.ks, &wid).unwrap() >= 1);
        let (from, pt) = decrypt_direct(&mut survivor.ks, sid, &w1, 2).unwrap();
        assert_eq!((from, pt.as_slice()), (wid, b"i am back".as_slice()));

        // And the conversation continues both ways on the new session.
        let w2 = encrypt_direct(&mut survivor.ks, sid, wid, b"welcome back", 3).unwrap();
        assert_eq!(
            decrypt_direct(&mut wiped.ks, wid, &w2, 3).unwrap().1,
            b"welcome back"
        );
    }

    #[test]
    fn distribution_rides_the_channel_into_a_working_group_decrypt() {
        use crate::groups::group_manager::GroupId;
        use crate::ratchet::sender_keys::{
            create_or_get_own_sender_key, decrypt_sender_key_message, encrypt_sender_key_message,
            install_sender_key,
        };

        // Full Stage 3 → Stage 4 integration: Alice sends Bob her
        // sender key over the 1:1 ratchet, Bob installs it under the
        // channel-authenticated sender id, and Alice's next v3 group
        // frame decrypts on Bob's side.
        let (mut a, mut b) = paired();
        let (aid, bid) = (a.kp.identity_id(), b.kp.identity_id());
        let group = GroupId::from_bytes([0xEE; 32]);
        let group_key = [0x55u8; 32];

        let dist = create_or_get_own_sender_key(&mut a.ks, &group, aid).unwrap();
        let w = encrypt_direct_distribution(&mut a.ks, aid, bid, &dist, 1).unwrap();

        let (sender, payload) = decrypt_direct_payload(&mut b.ks, bid, &w, 1).unwrap();
        assert_eq!(sender, aid);
        let received = match payload {
            DirectPayload::SenderKeyDistribution(d) => d,
            other => panic!("expected distribution, got {other:?}"),
        };
        install_sender_key(&mut b.ks, sender, &received).unwrap();

        let frame =
            encrypt_sender_key_message(&mut a.ks, &group, &group_key, aid, b"group hello").unwrap();
        let (gid, from, pt) = decrypt_sender_key_message(&mut b.ks, &group_key, &frame).unwrap();
        assert_eq!(
            (gid, from, pt.as_slice()),
            (group, aid, b"group hello".as_slice())
        );
    }
}
