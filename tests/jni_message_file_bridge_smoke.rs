//! Semantic smoke tests for the Android-facing message/file JNI bridge.
//!
//! These tests deliberately avoid trying to instantiate a JVM/JNIEnv in a Rust
//! unit test. Instead they test the Rust core behavior that the JNI methods must
//! wrap, and they separately assert that the Kotlin/Rust native symbols exist.
//!
//! Contract under test:
//! - nativeEncryptMessage must produce non-empty opaque envelope bytes.
//! - nativeDecryptMessage must recover the original message bytes/string.
//! - nativeEncryptFile must produce non-empty opaque envelope bytes.
//! - nativeDecryptFile must recover the original file bytes.
//!
//! The JNI contract checker verifies symbol matching. These tests verify the
//! underlying Rust encryption/decryption semantics do not regress.

use qubee_crypto::groups::group_handshake::{
    generate_ephemeral_kyber, sign_request_join, GroupHandshake, MemberAddedBody, RequestJoinBody,
};
use qubee_crypto::groups::group_manager::{GroupId, GroupManager};
use qubee_crypto::groups::group_message::{
    decrypt_group_message, encrypt_group_message, MAGIC_GROUP_MESSAGE,
};
use qubee_crypto::groups::handshake_handlers::{
    process_join_accepted, process_request_join, HandshakeOutcome,
};
use qubee_crypto::identity::identity_key::{HybridSignature, IdentityKeyPair};
use qubee_crypto::storage::secure_keystore::{install_test_password, SecureKeyStore};
use tempfile::TempDir;

fn fresh_device(label: &str) -> (TempDir, IdentityKeyPair, GroupManager) {
    install_test_password();
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(format!("{label}.db"));
    let ks = SecureKeyStore::new(&path).expect("keystore");
    let gm = GroupManager::new(ks).expect("group manager");
    let kp = IdentityKeyPair::generate().expect("identity");
    (dir, kp, gm)
}

fn create_alice_group() -> (TempDir, IdentityKeyPair, GroupManager, GroupId, String, String) {
    use qubee_crypto::groups::group_manager::{GroupSettings, GroupType};

    let (alice_dir, alice_kp, mut alice_gm) = fresh_device("alice");
    let alice_id = alice_kp.identity_id();
    let group_id = alice_gm
        .create_group(
            alice_id,
            alice_kp.public_key(),
            "JNI bridge smoke".to_string(),
            String::new(),
            GroupType::Private,
            GroupSettings::default(),
        )
        .expect("create Alice group");
    alice_gm.ensure_group_key(group_id).expect("group key");
    let invitation = alice_gm
        .create_invitation(group_id, alice_id, None, None)
        .expect("invitation");

    (
        alice_dir,
        alice_kp,
        alice_gm,
        group_id,
        invitation.invitation_code,
        invitation.inviter_name,
    )
}

fn join_bob_to_alice(
    alice_kp: &IdentityKeyPair,
    alice_gm: &mut GroupManager,
    group_id: GroupId,
    invitation_code: String,
    inviter_name: String,
) -> (
    TempDir,
    IdentityKeyPair,
    GroupManager,
    MemberAddedBody,
    HybridSignature,
) {
    let (bob_dir, bob_kp, mut bob_gm) = fresh_device("bob");
    bob_gm
        .record_external_invite_acceptance(
            group_id,
            "JNI bridge smoke",
            alice_kp.identity_id(),
            &inviter_name,
            &invitation_code,
        )
        .expect("record Bob invite acceptance");

    let (kyber_pub, kyber_secret) = generate_ephemeral_kyber();
    let (req_body, req_sig) = match sign_request_join(
        &bob_kp,
        RequestJoinBody {
            group_id,
            invitation_code,
            joiner_public_key: bob_kp.public_key(),
            joiner_display_name: "Bob".to_string(),
            joiner_kyber_pub: kyber_pub,
        },
    )
    .expect("sign request join")
    {
        GroupHandshake::RequestJoin { body, signature } => (body, signature),
        _ => unreachable!("sign_request_join must return RequestJoin"),
    };

    let (acc_body, acc_sig, ma_body, ma_sig) =
        match process_request_join(alice_gm, alice_kp, &req_body, &req_sig)
            .expect("Alice accepts Bob")
        {
            HandshakeOutcome::Accept {
                body,
                signature,
                member_added_body,
                member_added_signature,
            } => (body, signature, member_added_body, member_added_signature),
            other => panic!("expected Accept, got {other:?}"),
        };

    process_join_accepted(
        &mut bob_gm,
        alice_kp.identity_id(),
        &acc_body,
        &acc_sig,
        &kyber_secret,
    )
    .expect("Bob processes join accepted");

    (bob_dir, bob_kp, bob_gm, ma_body, ma_sig)
}

#[test]
fn jni_message_bridge_core_semantics_non_empty_envelope_and_round_trip() {
    let (_alice_dir, alice_kp, mut alice_gm, group_id, code, inviter_name) = create_alice_group();
    let alice_id = alice_kp.identity_id();
    let (_bob_dir, _bob_kp, bob_gm, _ma_body, _ma_sig) =
        join_bob_to_alice(&alice_kp, &mut alice_gm, group_id, code, inviter_name);

    let plaintext = b"Qubee JNI message bridge smoke test";
    let envelope = encrypt_group_message(&alice_gm, &alice_kp, group_id, plaintext)
        .expect("nativeEncryptMessage core path should encrypt");

    assert!(!envelope.is_empty(), "encrypted message envelope must be non-empty");
    assert!(
        envelope.starts_with(MAGIC_GROUP_MESSAGE),
        "message envelope must use the group-message wire prefix"
    );
    assert_ne!(
        envelope,
        plaintext,
        "encrypted message envelope must not equal plaintext bytes"
    );

    let decrypted = decrypt_group_message(&bob_gm, &envelope)
        .expect("nativeDecryptMessage core path should decrypt");

    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_id, alice_id);
    assert_eq!(decrypted.group_id, group_id);
    assert!(decrypted.timestamp > 0);
}

#[test]
fn jni_file_bridge_core_semantics_non_empty_envelope_and_round_trip() {
    let (_alice_dir, alice_kp, mut alice_gm, group_id, code, inviter_name) = create_alice_group();
    let alice_id = alice_kp.identity_id();
    let (_bob_dir, _bob_kp, bob_gm, _ma_body, _ma_sig) =
        join_bob_to_alice(&alice_kp, &mut alice_gm, group_id, code, inviter_name);

    let file_bytes: Vec<u8> = (0..=255).cycle().take(4096).collect();
    let envelope = encrypt_group_message(&alice_gm, &alice_kp, group_id, &file_bytes)
        .expect("nativeEncryptFile core path should encrypt binary bytes");

    assert!(!envelope.is_empty(), "encrypted file envelope must be non-empty");
    assert!(
        envelope.starts_with(MAGIC_GROUP_MESSAGE),
        "file envelope must use the group-message wire prefix until a dedicated file envelope exists"
    );
    assert_ne!(
        envelope,
        file_bytes,
        "encrypted file envelope must not equal raw file bytes"
    );

    let decrypted = decrypt_group_message(&bob_gm, &envelope)
        .expect("nativeDecryptFile core path should decrypt binary bytes");

    assert_eq!(decrypted.plaintext, file_bytes);
    assert_eq!(decrypted.sender_id, alice_id);
    assert_eq!(decrypted.group_id, group_id);
    assert!(decrypted.timestamp > 0);
}

#[test]
fn android_jni_message_file_symbols_are_present() {
    let kotlin = include_str!("../app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt");
    let rust = include_str!("../src/jni_api.rs");

    for symbol in [
        "nativeEncryptMessage",
        "nativeDecryptMessage",
        "nativeEncryptFile",
        "nativeDecryptFile",
        "nativeSetKeystorePassword",
        "nativeRegisterVideoInputs",
    ] {
        assert!(
            kotlin.contains(&format!("external fun {symbol}")),
            "QubeeManager.kt must declare external fun {symbol}(...)"
        );
        assert!(
            rust.contains(&format!(
                "Java_com_qubee_messenger_crypto_QubeeManager_{symbol}"
            )),
            "src/jni_api.rs must export Java_com_qubee_messenger_crypto_QubeeManager_{symbol}"
        );
    }
}
