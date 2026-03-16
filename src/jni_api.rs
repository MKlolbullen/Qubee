use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray};
use jni::JNIEnv;

use crate::native_contract;

fn null_array() -> jbyteArray {
    std::ptr::null_mut()
}

fn byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => null_array(),
    }
}

fn result_array(env: &mut JNIEnv, result: anyhow::Result<Vec<u8>>) -> jbyteArray {
    let payload = native_contract::call_result(result);
    byte_array(env, &payload)
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInitialize(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    1
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityBundle(
    mut env: JNIEnv,
    _class: JClass,
    display_name: JString,
    device_label: JString,
    relay_handle: JString,
    device_id: JString,
) -> jbyteArray {
    let display_name: String = match env.get_string(&display_name) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let device_label: String = match env.get_string(&device_label) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let relay_handle: String = match env.get_string(&relay_handle) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let device_id: String = match env.get_string(&device_id) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };

    match native_contract::generate_identity_bundle(&display_name, &device_label, &relay_handle, &device_id) {
        Ok(bytes) => byte_array(&mut env, &bytes),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateIdentityBundleResult(
    mut env: JNIEnv,
    _class: JClass,
    display_name: JString,
    device_label: JString,
    relay_handle: JString,
    device_id: JString,
) -> jbyteArray {
    let display_name: String = match env.get_string(&display_name) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let device_label: String = match env.get_string(&device_label) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let relay_handle: String = match env.get_string(&relay_handle) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let device_id: String = match env.get_string(&device_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };

    result_array(
        &mut env,
        native_contract::generate_identity_bundle(&display_name, &device_label, &relay_handle, &device_id),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRestoreIdentityBundle(
    env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
) -> jboolean {
    let identity_bytes = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if native_contract::restore_identity_bundle(&identity_bytes).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRestoreIdentityBundleResult(
    mut env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
) -> jbyteArray {
    let identity_bytes = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::restore_identity_bundle(&identity_bytes).map(|_| Vec::new()))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeSignRelayChallenge(
    mut env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
    challenge: JByteArray,
) -> jbyteArray {
    let identity_bytes = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    let challenge_bytes = match env.convert_byte_array(challenge) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::sign_relay_challenge(&identity_bytes, &challenge_bytes) {
        Ok(signature) => byte_array(&mut env, &signature),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeSignRelayChallengeResult(
    mut env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
    challenge: JByteArray,
) -> jbyteArray {
    let identity_bytes = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let challenge_bytes = match env.convert_byte_array(challenge) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::sign_relay_challenge(&identity_bytes, &challenge_bytes))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateRatchetSession(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    their_public_key: JByteArray,
    is_initiator: jboolean,
) -> jbyteArray {
    let contact_id: String = match env.get_string(&contact_id) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let peer_bundle_bytes = match env.convert_byte_array(their_public_key) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::create_session_bundle(&contact_id, &peer_bundle_bytes, is_initiator != 0) {
        Ok(bundle) => byte_array(&mut env, &bundle),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateHybridSessionInit(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    peer_public_bundle: JByteArray,
) -> jbyteArray {
    let contact_id: String = match env.get_string(&contact_id) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let peer_bundle_bytes = match env.convert_byte_array(peer_public_bundle) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::create_hybrid_session_init(&contact_id, &peer_bundle_bytes) {
        Ok(payload) => byte_array(&mut env, &payload),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeAcceptHybridSessionInit(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    session_init: JByteArray,
) -> jbyteArray {
    let contact_id: String = match env.get_string(&contact_id) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let init_bytes = match env.convert_byte_array(session_init) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::accept_hybrid_session_init(&contact_id, &init_bytes) {
        Ok(payload) => byte_array(&mut env, &payload),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCreateRatchetSessionResult(
    mut env: JNIEnv,
    _class: JClass,
    contact_id: JString,
    their_public_key: JByteArray,
    is_initiator: jboolean,
) -> jbyteArray {
    let contact_id: String = match env.get_string(&contact_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let peer_bundle_bytes = match env.convert_byte_array(their_public_key) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(
        &mut env,
        native_contract::create_session_bundle(&contact_id, &peer_bundle_bytes, is_initiator != 0),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRestoreSessionBundle(
    env: JNIEnv,
    _class: JClass,
    session_bundle: JByteArray,
) -> jboolean {
    let session_bytes = match env.convert_byte_array(session_bundle) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if native_contract::restore_session_bundle(&session_bytes).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRestoreSessionBundleResult(
    mut env: JNIEnv,
    _class: JClass,
    session_bundle: JByteArray,
) -> jbyteArray {
    let session_bytes = match env.convert_byte_array(session_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::restore_session_bundle(&session_bytes).map(|_| Vec::new()))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeExportSessionBundleResult(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::export_session_bundle(&session_id))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeMarkSessionRekeyRequiredResult(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::mark_session_rekey_required(&session_id))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeMarkSessionRelinkRequiredResult(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::mark_session_relink_required(&session_id))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeRotateSessionBundleResult(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    peer_bundle: JByteArray,
    is_initiator: jboolean,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let peer_bundle_bytes = match env.convert_byte_array(peer_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(
        &mut env,
        native_contract::rotate_session_bundle(&session_id, &peer_bundle_bytes, is_initiator != 0),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let plaintext = match env.convert_byte_array(plaintext) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::encrypt_message(&session_id, &plaintext) {
        Ok(ciphertext) => byte_array(&mut env, &ciphertext),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeEncryptMessageResult(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    plaintext: JByteArray,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let plaintext = match env.convert_byte_array(plaintext) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::encrypt_message(&session_id, &plaintext))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessage(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(_) => return null_array(),
    };
    let ciphertext = match env.convert_byte_array(ciphertext) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::decrypt_message(&session_id, &ciphertext) {
        Ok(plaintext) => byte_array(&mut env, &plaintext),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeDecryptMessageResult(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
    ciphertext: JByteArray,
) -> jbyteArray {
    let session_id: String = match env.get_string(&session_id) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let ciphertext = match env.convert_byte_array(ciphertext) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::decrypt_message(&session_id, &ciphertext))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeExportInvitePayload(
    mut env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
) -> jbyteArray {
    let identity_bytes = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::export_invite_payload(&identity_bytes) {
        Ok(bytes) => byte_array(&mut env, &bytes),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeInspectInvitePayload(
    mut env: JNIEnv,
    _class: JClass,
    invite_payload: JByteArray,
) -> jbyteArray {
    let payload = match env.convert_byte_array(invite_payload) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::inspect_invite_payload(&payload) {
        Ok(bytes) => byte_array(&mut env, &bytes),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeComputeSafetyCode(
    mut env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
    peer_public_bundle: JByteArray,
) -> jbyteArray {
    let identity = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    let peer = match env.convert_byte_array(peer_public_bundle) {
        Ok(value) => value,
        Err(_) => return null_array(),
    };
    match native_contract::compute_safety_code(&identity, &peer) {
        Ok(bytes) => byte_array(&mut env, &bytes),
        Err(_) => null_array(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateKeyOwnershipProofResult(
    mut env: JNIEnv,
    _class: JClass,
    identity_bundle: JByteArray,
) -> jbyteArray {
    let identity_bytes = match env.convert_byte_array(identity_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::generate_key_ownership_proof(&identity_bytes))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyKeyOwnershipProofResult(
    mut env: JNIEnv,
    _class: JClass,
    proof: JByteArray,
    public_bundle: JByteArray,
) -> jbyteArray {
    let proof_bytes = match env.convert_byte_array(proof) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let bundle_bytes = match env.convert_byte_array(public_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(
        &mut env,
        native_contract::verify_key_ownership_proof(&proof_bytes, &bundle_bytes).map(|_| Vec::new()),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeGenerateKeyRotationProofResult(
    mut env: JNIEnv,
    _class: JClass,
    old_identity_bundle: JByteArray,
    new_identity_bundle: JByteArray,
) -> jbyteArray {
    let old_bytes = match env.convert_byte_array(old_identity_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let new_bytes = match env.convert_byte_array(new_identity_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(&mut env, native_contract::generate_key_rotation_proof(&old_bytes, &new_bytes))
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeVerifyKeyRotationProofResult(
    mut env: JNIEnv,
    _class: JClass,
    rotation_proof: JByteArray,
    old_commitment_base64: JString,
    new_public_bundle: JByteArray,
) -> jbyteArray {
    let proof_bytes = match env.convert_byte_array(rotation_proof) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let commitment: String = match env.get_string(&old_commitment_base64) {
        Ok(value) => value.into(),
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    let bundle_bytes = match env.convert_byte_array(new_public_bundle) {
        Ok(value) => value,
        Err(error) => return result_array(&mut env, Err(anyhow::anyhow!(error.to_string()))),
    };
    result_array(
        &mut env,
        native_contract::verify_key_rotation_proof(&proof_bytes, &commitment, &bundle_bytes).map(|_| Vec::new()),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_qubee_messenger_crypto_QubeeManager_nativeCleanup(
    _env: JNIEnv,
    _class: JClass,
) {
    native_contract::zeroize_all();
    native_contract::clear_sessions();
}
