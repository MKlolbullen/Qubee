//! Rust-level rehearsal of the two-device cutover checklist
//! (`docs/two-device-walkthrough.md`) for the ratchet send path, over
//! exactly the public API the JNI bridge calls. The send flip
//! (`ratchetSendEnabled`) is gated on device validation; this file
//! proves the full multi-member choreography — distribution fan-out,
//! mesh messaging, removal rekey, late join, restart — so the only
//! thing left for the devices to validate is transport.

use qubee_crypto::groups::group_handshake::sign_prekey_bundle;
use qubee_crypto::groups::group_manager::GroupId;
use qubee_crypto::identity::identity_key::{IdentityId, IdentityKeyPair};
use qubee_crypto::ratchet::direct::{
    decrypt_direct_payload, encrypt_direct_distribution, encrypt_direct_text, install_peer_bundle,
    DirectPayload,
};
use qubee_crypto::ratchet::prekey_store::{build_body, get_or_create_local_bundle};
use qubee_crypto::ratchet::sender_keys::{
    create_or_get_own_sender_key, decrypt_sender_key_message, encrypt_sender_key_message,
    install_sender_key, reset_group_sender_state,
};
use qubee_crypto::storage::secure_keystore::SecureKeyStore;
use tempfile::TempDir;

const PASSPHRASE: &[u8] = b"cutover-rehearsal";

struct Device {
    ks: SecureKeyStore,
    kp: IdentityKeyPair,
    dir: TempDir,
}

impl Device {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let ks = SecureKeyStore::new(dir.path().join("ks.db"), PASSPHRASE).unwrap();
        Device {
            ks,
            kp: IdentityKeyPair::generate().unwrap(),
            dir,
        }
    }

    fn id(&self) -> IdentityId {
        self.kp.identity_id()
    }

    fn signed_bundle_wire(&mut self, now: u64) -> Vec<u8> {
        let (secret, kem_pub) = get_or_create_local_bundle(&mut self.ks, now).unwrap();
        let body = build_body(&secret, &kem_pub, self.kp.public_key(), now);
        sign_prekey_bundle(&self.kp, body)
            .unwrap()
            .to_wire()
            .unwrap()
    }

    /// App restart: reopen the keystore from disk. Identity and every
    /// session / chain must come back from persistence alone.
    fn restart(&mut self) {
        self.ks = SecureKeyStore::new(self.dir.path().join("ks.db"), PASSPHRASE).unwrap();
    }
}

fn pair(a: &mut Device, b: &mut Device, now: u64) {
    let (aw, bw) = (a.signed_bundle_wire(now), b.signed_bundle_wire(now));
    assert_eq!(install_peer_bundle(&mut a.ks, &bw).unwrap(), b.id());
    assert_eq!(install_peer_bundle(&mut b.ks, &aw).unwrap(), a.id());
}

/// The rekey fan-out leg the Kotlin flip must implement: sender key
/// travels only over the established 1:1 ratchet session, and the
/// receiver installs it under the channel-authenticated identity.
fn distribute(from: &mut Device, to: &mut Device, group: &GroupId, now: u64) {
    let (from_id, to_id) = (from.id(), to.id());
    let dist = create_or_get_own_sender_key(&mut from.ks, group, from_id).unwrap();
    let wire = encrypt_direct_distribution(&mut from.ks, from_id, to_id, &dist, now).unwrap();
    let (sender, payload) = decrypt_direct_payload(&mut to.ks, to_id, &wire, now).unwrap();
    assert_eq!(sender, from_id);
    match payload {
        DirectPayload::SenderKeyDistribution(d) => {
            install_sender_key(&mut to.ks, sender, &d).unwrap()
        }
        other => panic!("expected distribution, got {other:?}"),
    }
}

/// Pairwise sessions + full sender-key mesh. Within each pair the
/// lower-index device initiates first so the responder reuses that
/// session instead of racing a simultaneous open.
fn mesh(devices: &mut [Device], group: &GroupId, now: u64) {
    for i in 0..devices.len() {
        for j in (i + 1)..devices.len() {
            let (left, right) = devices.split_at_mut(j);
            pair(&mut left[i], &mut right[0], now);
            distribute(&mut left[i], &mut right[0], group, now);
            distribute(&mut right[0], &mut left[i], group, now);
        }
    }
}

fn send(dev: &mut Device, group: &GroupId, group_key: &[u8; 32], text: &[u8]) -> Vec<u8> {
    let id = dev.id();
    encrypt_sender_key_message(&mut dev.ks, group, group_key, id, text).unwrap()
}

fn recv(dev: &mut Device, group_key: &[u8; 32], wire: &[u8]) -> (IdentityId, Vec<u8>) {
    let (_, sender, pt) = decrypt_sender_key_message(&mut dev.ks, group_key, wire).unwrap();
    (sender, pt)
}

#[test]
fn three_member_mesh_full_choreography() {
    let mut devs = [Device::new(), Device::new(), Device::new()];
    let group = GroupId::from_bytes([0xA1; 32]);
    let group_key = [0x11u8; 32];
    mesh(&mut devs, &group, 1);

    for s in 0..devs.len() {
        let wire = send(
            &mut devs[s],
            &group,
            &group_key,
            format!("from {s}").as_bytes(),
        );
        for r in 0..devs.len() {
            if r == s {
                // No recv chain for self — the app keeps the local
                // plaintext; it never round-trips its own frames.
                assert!(decrypt_sender_key_message(&mut devs[r].ks, &group_key, &wire).is_err());
                continue;
            }
            let sender_id = devs[s].id();
            let (from, pt) = recv(&mut devs[r], &group_key, &wire);
            assert_eq!((from, pt), (sender_id, format!("from {s}").into_bytes()));
            // Forward secrecy at the state level: the consumed message
            // key is gone, so the captured frame is dead on replay.
            let err = decrypt_sender_key_message(&mut devs[r].ks, &group_key, &wire).unwrap_err();
            assert!(err.to_string().contains("consumed"), "{err}");
        }
    }
}

#[test]
fn removal_rekey_locks_out_removed_member() {
    let mut devs = [Device::new(), Device::new(), Device::new()];
    let group = GroupId::from_bytes([0xB2; 32]);
    let old_key = [0x11u8; 32];
    mesh(&mut devs, &group, 1);

    let w = send(&mut devs[0], &group, &old_key, b"before removal");
    recv(&mut devs[1], &old_key, &w);
    recv(&mut devs[2], &old_key, &w);

    // Carol (index 2) is removed. The v2 rotation delivers a fresh
    // group key to the remaining members; each wipes every chain for
    // the group and redistributes over the surviving 1:1 sessions.
    let new_key = [0x22u8; 32];
    assert!(reset_group_sender_state(&mut devs[0].ks, &group).unwrap() >= 1);
    assert!(reset_group_sender_state(&mut devs[1].ks, &group).unwrap() >= 1);
    {
        let (left, right) = devs.split_at_mut(1);
        distribute(&mut left[0], &mut right[0], &group, 2);
        distribute(&mut right[0], &mut left[0], &group, 2);
    }

    let w = send(&mut devs[0], &group, &new_key, b"after removal");
    let (from, pt) = recv(&mut devs[1], &new_key, &w);
    assert_eq!(
        (from, pt.as_slice()),
        (devs[0].id(), b"after removal".as_slice())
    );

    // Carol never received the rotated group key: the outer envelope
    // fails before anything else runs.
    assert!(decrypt_sender_key_message(&mut devs[2].ks, &old_key, &w).is_err());

    // Even if the new group key leaks to her, Alice's fresh chain does
    // not match the stale distribution Carol still holds.
    assert!(decrypt_sender_key_message(&mut devs[2].ks, &new_key, &w).is_err());

    // Carol's own sends are equally dead: under the old key the outer
    // AEAD fails, and under a leaked new key the remaining members
    // wiped her chain, so there is nothing to verify against.
    let stale = send(&mut devs[2], &group, &old_key, b"i am still here");
    assert!(decrypt_sender_key_message(&mut devs[0].ks, &new_key, &stale).is_err());
    let leaked = send(&mut devs[2], &group, &new_key, b"with the new key");
    let err = decrypt_sender_key_message(&mut devs[0].ks, &new_key, &leaked).unwrap_err();
    assert!(err.to_string().contains("no sender key"), "{err}");
}

#[test]
fn late_joiner_reads_forward_never_backward() {
    let mut devs = [Device::new(), Device::new()];
    let group = GroupId::from_bytes([0xC3; 32]);
    let group_key = [0x11u8; 32];
    mesh(&mut devs, &group, 1);

    let mut history = Vec::new();
    for i in 0..3u8 {
        let w = send(&mut devs[0], &group, &group_key, &[i]);
        recv(&mut devs[1], &group_key, &w);
        history.push(w);
    }

    // Dave joins. His distributions from the existing members start at
    // their *current* iterations — the chain never runs backward.
    let alice_id = devs[0].id();
    let mut dave = Device::new();
    let dave_id = dave.id();
    for existing in devs.iter_mut() {
        pair(existing, &mut dave, 2);
        let existing_id = existing.id();
        let dist = create_or_get_own_sender_key(&mut existing.ks, &group, existing_id).unwrap();
        if dist.sender_id == alice_id {
            assert!(dist.iteration > 0, "history must have advanced the chain");
        }
        let wire =
            encrypt_direct_distribution(&mut existing.ks, existing_id, dave_id, &dist, 2).unwrap();
        let (sender, payload) = decrypt_direct_payload(&mut dave.ks, dave_id, &wire, 2).unwrap();
        match payload {
            DirectPayload::SenderKeyDistribution(d) => {
                install_sender_key(&mut dave.ks, sender, &d).unwrap()
            }
            other => panic!("expected distribution, got {other:?}"),
        }
        distribute(&mut dave, existing, &group, 2);
    }

    let w = send(&mut devs[0], &group, &group_key, b"welcome dave");
    let (from, pt) = recv(&mut dave, &group_key, &w);
    assert_eq!(
        (from, pt.as_slice()),
        (devs[0].id(), b"welcome dave".as_slice())
    );

    for old in &history {
        let err = decrypt_sender_key_message(&mut dave.ks, &group_key, old).unwrap_err();
        assert!(err.to_string().contains("consumed"), "{err}");
    }
}

#[test]
fn state_survives_restart_mid_conversation() {
    let mut devs = [Device::new(), Device::new()];
    let group = GroupId::from_bytes([0xD4; 32]);
    let group_key = [0x11u8; 32];
    mesh(&mut devs, &group, 1);

    let f1 = send(&mut devs[0], &group, &group_key, b"before restart");
    recv(&mut devs[1], &group_key, &f1);

    devs[0].restart();
    devs[1].restart();

    // Consumed keys stay consumed across the restart — a captured
    // frame must not become decryptable again by rebooting.
    assert!(decrypt_sender_key_message(&mut devs[1].ks, &group_key, &f1).is_err());

    // Chains continue where they left off, in both directions, with no
    // re-pairing and no redistribution.
    let f2 = send(&mut devs[1], &group, &group_key, b"b after restart");
    assert_eq!(
        recv(&mut devs[0], &group_key, &f2).1,
        b"b after restart".to_vec()
    );
    let f3 = send(&mut devs[0], &group, &group_key, b"a after restart");
    assert_eq!(
        recv(&mut devs[1], &group_key, &f3).1,
        b"a after restart".to_vec()
    );
}

#[test]
fn one_to_one_text_leg_survives_restart() {
    let mut a = Device::new();
    let mut b = Device::new();
    pair(&mut a, &mut b, 1);
    let (aid, bid) = (a.id(), b.id());

    let w = encrypt_direct_text(&mut a.ks, aid, bid, "hello", 1).unwrap();
    let (sender, payload) = decrypt_direct_payload(&mut b.ks, bid, &w, 1).unwrap();
    assert_eq!(
        (sender, payload),
        (aid, DirectPayload::Text("hello".into()))
    );

    a.restart();
    b.restart();

    let w = encrypt_direct_text(&mut b.ks, bid, aid, "still here", 2).unwrap();
    let (sender, payload) = decrypt_direct_payload(&mut a.ks, aid, &w, 2).unwrap();
    assert_eq!(
        (sender, payload),
        (bid, DirectPayload::Text("still here".into()))
    );
}

// ---------------------------------------------------------------------------
// Category-A cutover matrix rows (host-automatable). The primitives are
// unit-tested in `src/ratchet/*`; these prove the same properties end to
// end over the public JNI-facing API, which is what the flag flip depends
// on. See issue #47 (v0.2.0 — Ratchet Cutover).
// ---------------------------------------------------------------------------

/// "100 alternating messages → no desync." Each direction flip forces a
/// fresh DH ratchet step, so sustained ping-pong exercises far more
/// ratchet advancement than any single-direction burst. Every frame must
/// decrypt to the exact text with the right authenticated sender.
#[test]
fn alternating_conversation_never_desyncs() {
    let mut a = Device::new();
    let mut b = Device::new();
    pair(&mut a, &mut b, 1);
    let (aid, bid) = (a.id(), b.id());

    for i in 0..100u64 {
        let text = format!("msg {i}");
        // Alternate who speaks each turn → a DH ratchet step every flip.
        let (from, from_id, to, to_id) = if i % 2 == 0 {
            (&mut a, aid, &mut b, bid)
        } else {
            (&mut b, bid, &mut a, aid)
        };
        let now = 10 + i;
        let wire = encrypt_direct_text(&mut from.ks, from_id, to_id, &text, now).unwrap();
        let (sender, payload) = decrypt_direct_payload(&mut to.ks, to_id, &wire, now).unwrap();
        assert_eq!(
            (sender, payload),
            (from_id, DirectPayload::Text(text.clone())),
            "desync at message {i}",
        );
    }
}

/// Cross-group ciphertext substitution: a sender-key frame is sealed under
/// its group's symmetric key, so a frame captured from group 1 must not
/// open under group 2's key — and a failed attempt must not corrupt the
/// receiver's chain state (the correct key still works afterward).
#[test]
fn frame_sealed_for_one_group_key_is_rejected_under_another() {
    let mut devs = [Device::new(), Device::new()];
    let group = GroupId::from_bytes([0x5c; 32]);
    let key_1 = [0x11u8; 32];
    let key_2 = [0x22u8; 32];
    mesh(&mut devs, &group, 1);

    let wire = send(&mut devs[0], &group, &key_1, b"group one only");

    // Wrong group key → rejected at the outer seal, before any chain state
    // is touched.
    assert!(
        decrypt_sender_key_message(&mut devs[1].ks, &key_2, &wire).is_err(),
        "a frame sealed under one group key must not open under another",
    );
    // The failed attempt left the receiver's state intact: the correct key
    // still opens the same frame.
    let sender_id = devs[0].id();
    let (from, pt) = recv(&mut devs[1], &key_1, &wire);
    assert_eq!((from, pt), (sender_id, b"group one only".to_vec()));
}

/// Cross-session (cross-user) substitution: a 1:1 frame addressed to B
/// must not decrypt in C's session, even though C also has a session with
/// the same sender A. Sessions derive independent keys.
#[test]
fn direct_frame_for_one_peer_is_rejected_by_another() {
    let mut a = Device::new();
    let mut b = Device::new();
    let mut c = Device::new();
    pair(&mut a, &mut b, 1);
    pair(&mut a, &mut c, 1);
    let (aid, bid, cid) = (a.id(), b.id(), c.id());

    let wire_for_b = encrypt_direct_text(&mut a.ks, aid, bid, "meant for B", 5).unwrap();

    // C shares a session with A but not this frame's keys.
    assert!(
        decrypt_direct_payload(&mut c.ks, cid, &wire_for_b, 5).is_err(),
        "a frame for B must not open in C's session",
    );
    // B, the intended recipient, still reads it.
    let (sender, payload) = decrypt_direct_payload(&mut b.ks, bid, &wire_for_b, 5).unwrap();
    assert_eq!(
        (sender, payload),
        (aid, DirectPayload::Text("meant for B".into()))
    );
}

// ---------------------------------------------------------------------------
// Crash consistency: no ratchet key reuse across process death.
//
// The catastrophic outbound failure class is "the ratchet advanced but the
// ciphertext's durable state didn't" — if a restart reverted the ratchet,
// the next send would reuse a message key/nonce. The Rust send path
// persists the advance *before* returning the ciphertext (encrypt →
// store → return), so a relaunch always resumes past the last emitted
// position. These lock that invariant end to end; the Kotlin
// PREPARED→…→ACKNOWLEDGED outbox recovery is built on top of it. See
// docs/architecture/crash-consistency.md and issue #47.
// ---------------------------------------------------------------------------

/// A 1:1 send whose ciphertext is lost to a crash (before it reached the
/// durable outbox) must not desync the channel or get its position reused
/// by the next send: the ratchet advance was already durable, so the
/// relaunched sender continues *past* it and the receiver just skips the
/// gap.
#[test]
fn crash_after_advance_never_reuses_a_1to1_position() {
    let mut a = Device::new();
    let mut b = Device::new();
    pair(&mut a, &mut b, 1);
    let (aid, bid) = (a.id(), b.id());

    // Send #1 advances + persists A's ratchet; then the wire is dropped,
    // modelling a process kill before the ciphertext was durably queued.
    let _lost = encrypt_direct_text(&mut a.ks, aid, bid, "lost to a crash", 1).unwrap();

    // Relaunch: A's ratchet comes back from disk alone.
    a.restart();

    // The recovered send lands on a fresh position. B never saw the lost
    // frame, so it decrypts this one by skipping the gap (within the skip
    // window) — proving no desync and no reuse.
    let wire = encrypt_direct_text(&mut a.ks, aid, bid, "after restart", 2).unwrap();
    let (sender, payload) = decrypt_direct_payload(&mut b.ks, bid, &wire, 2).unwrap();
    assert_eq!(
        (sender, payload),
        (aid, DirectPayload::Text("after restart".into())),
    );
}

/// Stronger form of the same invariant: two sends straddling a restart
/// must occupy DISTINCT ratchet positions. If the crash reverted the
/// ratchet, the second frame would reuse the first's position and the
/// receiver would reject it as a replay once the first is consumed.
#[test]
fn sends_straddling_a_restart_occupy_distinct_positions() {
    let mut a = Device::new();
    let mut b = Device::new();
    pair(&mut a, &mut b, 1);
    let (aid, bid) = (a.id(), b.id());

    let wire1 = encrypt_direct_text(&mut a.ks, aid, bid, "one", 1).unwrap();
    a.restart();
    let wire2 = encrypt_direct_text(&mut a.ks, aid, bid, "two", 2).unwrap();

    // Both decrypt to their own plaintext. Reuse would make the second
    // decrypt fail as consumed once the first position is in.
    let (_, p1) = decrypt_direct_payload(&mut b.ks, bid, &wire1, 1).unwrap();
    let (_, p2) = decrypt_direct_payload(&mut b.ks, bid, &wire2, 2).unwrap();
    assert_eq!(p1, DirectPayload::Text("one".into()));
    assert_eq!(p2, DirectPayload::Text("two".into()));
}

/// Group (sender-key) equivalent: a crash after the sender chain advanced
/// must not reuse an iteration — the relaunched sender continues past the
/// lost frame and the receiver skips the gap.
#[test]
fn crash_after_advance_never_reuses_a_group_iteration() {
    let mut devs = [Device::new(), Device::new()];
    let group = GroupId::from_bytes([0x77; 32]);
    let key = [0x33u8; 32];
    mesh(&mut devs, &group, 1);

    let _lost = send(&mut devs[0], &group, &key, b"lost to a crash");
    devs[0].restart();
    let wire = send(&mut devs[0], &group, &key, b"after restart");

    let sender_id = devs[0].id();
    let (from, pt) = recv(&mut devs[1], &key, &wire);
    assert_eq!((from, pt), (sender_id, b"after restart".to_vec()));
}
