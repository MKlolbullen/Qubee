//! Fuzz-lite robustness for the wire parsers (v0.2.0 ratchet cutover,
//! issue #47). Every public entry point that consumes untrusted bytes
//! must fail gracefully (`None` / `Err`) on arbitrary, malformed, or
//! truncated input — never panic, never over-read, never allocate on an
//! attacker-controlled length. This is the in-CI form of "fuzz the
//! protocol parsers"; a `cargo-fuzz` target set is future infra.
//!
//! The pinned vectors in `wire_stability.rs` prove one valid input round-
//! trips; these prove *invalid* inputs are handled safely.

use proptest::prelude::*;
use qubee_crypto::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, RequestJoinBody,
};
use qubee_crypto::groups::group_invite::InvitePayload;
use qubee_crypto::groups::group_manager::GroupId;
use qubee_crypto::identity::identity_key::{IdentityId, IdentityKey, IdentityKeyPair};
use qubee_crypto::ratchet::direct::inspect_direct_sender;
use qubee_crypto::ratchet::direct_message::DirectMessage;
use qubee_crypto::ratchet::double_ratchet::MessageHeader;
use qubee_crypto::ratchet::sender_keys::extract_v3_message_id;

fn valid_request_join_wire() -> Vec<u8> {
    let kp = IdentityKeyPair::generate().unwrap();
    let (kyber_pub, _) = generate_ephemeral_kyber();
    let body = RequestJoinBody {
        group_id: GroupId::from_bytes([7u8; 32]),
        invitation_code: "code".into(),
        joiner_public_key: kp.public_key(),
        joiner_display_name: "Bob".into(),
        joiner_kyber_pub: kyber_pub,
        joiner_peer_id: "12D3KooWBob".into(),
    };
    sign_request_join(&kp, body).unwrap().to_wire().unwrap()
}

fn valid_direct_message_wire() -> Vec<u8> {
    DirectMessage {
        sender_id: IdentityId::from([3u8; 32]),
        initial: None,
        header: MessageHeader {
            dh: [8u8; 32],
            pn: 1,
            n: 2,
        },
        ciphertext: vec![0x11, 0x22, 0x33],
    }
    .to_wire()
    .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Arbitrary bytes into every byte-consuming parser: no panic, no
    /// unbounded allocation.
    #[test]
    fn parsers_never_panic_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let _ = GroupHandshake::from_wire(&bytes);
        let _ = DirectMessage::from_wire(&bytes);
        let _ = inspect_direct_sender(&bytes);
        let _ = IdentityKey::from_bytes(&bytes);
        let _ = extract_v3_message_id(&[0u8; 32], &bytes);
    }

    /// Arbitrary strings into the invite-link parser: no panic.
    #[test]
    fn invite_link_parser_never_panics(s in ".{0,512}") {
        let _ = InvitePayload::from_invite_link(&s);
    }

    /// Handshake magic + arbitrary tail drives the bounded bincode path
    /// with attacker-controlled length prefixes.
    #[test]
    fn magic_framed_arbitrary_bytes_decode_gracefully(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let mut framed = b"QUBEE_GHS\x01".to_vec();
        framed.extend_from_slice(&bytes);
        let _ = GroupHandshake::from_wire(&framed);
    }
}

/// Truncation at every byte offset of a valid frame must be *rejected*
/// by that frame's own parser (not merely not-panic), and must not panic
/// any other parser. Only the full frame parses — a regression that
/// accepted a short frame would fail here. Catches over-reads and
/// lenient decoders a single fixed vector wouldn't.
#[test]
fn truncated_valid_frames_are_rejected_and_never_panic() {
    // RequestJoin handshake frame: every proper prefix must fail to parse
    // as a handshake, and must not panic the other parsers.
    let hs = valid_request_join_wire();
    for n in 0..hs.len() {
        let prefix = &hs[..n];
        assert!(
            GroupHandshake::from_wire(prefix).is_none(),
            "truncated handshake prefix (len {n}) was accepted",
        );
        let _ = DirectMessage::from_wire(prefix);
        let _ = inspect_direct_sender(prefix);
        let _ = IdentityKey::from_bytes(prefix);
    }

    // DirectMessage frame: same, against its own parser.
    let dm = valid_direct_message_wire();
    for n in 0..dm.len() {
        let prefix = &dm[..n];
        assert!(
            DirectMessage::from_wire(prefix).is_none(),
            "truncated direct-message prefix (len {n}) was accepted",
        );
        let _ = GroupHandshake::from_wire(prefix);
        let _ = IdentityKey::from_bytes(prefix);
    }

    // The full frames still parse as their own type.
    assert!(GroupHandshake::from_wire(&valid_request_join_wire()).is_some());
    assert!(DirectMessage::from_wire(&valid_direct_message_wire()).is_some());
}

/// A crafted oversized length prefix must be rejected as a decode error,
/// never drive an allocation. `IdentityKey::from_bytes` uses bincode
/// directly (not the 512 KB-bounded wire decoder used by `from_wire`), so
/// this pins that serde's cautious-capacity guard keeps it safe: a frame
/// claiming `u64::MAX` elements with almost no payload fails cleanly.
#[test]
fn identity_key_oversized_length_prefix_is_not_allocated() {
    let mut evil = u64::MAX.to_le_bytes().to_vec();
    evil.extend_from_slice(&[0u8; 16]);
    assert!(IdentityKey::from_bytes(&evil).is_err());
}

/// Single-byte corruption at every offset of a valid handshake frame
/// never panics (it may decode structurally, but a downstream signature
/// check would reject it — this only asserts parser safety).
#[test]
fn single_byte_corruption_never_panics() {
    let wire = valid_request_join_wire();
    for i in 0..wire.len() {
        let mut bad = wire.clone();
        bad[i] ^= 0xFF;
        let _ = GroupHandshake::from_wire(&bad);
    }
}
