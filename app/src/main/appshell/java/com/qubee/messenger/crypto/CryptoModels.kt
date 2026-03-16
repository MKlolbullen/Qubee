package com.qubee.messenger.crypto

data class IdentityMaterial(
    val displayName: String,
    val deviceLabel: String,
    val identityFingerprint: String,
    val publicBundleBase64: String,
    val identityBundleBase64: String,
    val relayHandle: String,
    val deviceId: String,
    val nativeBacked: Boolean,
)

data class SessionMaterial(
    val conversationId: String,
    val sessionId: String,
    val peerHandle: String,
    val keyMaterialBase64: String,
    val nativeBacked: Boolean,
    val state: String,
    val bootstrapPayloadBase64: String? = null,
    val algorithm: String = if (nativeBacked) "ml-kem-768+x25519+chacha20poly1305" else "aes-gcm-shell",
)

data class EncryptedPayload(
    val ciphertextBase64: String,
    val algorithm: String,
)
