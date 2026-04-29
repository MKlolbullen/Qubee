package com.qubee.messenger.crypto

/**
 * Kotlin-side encrypted payload containers used by the Android repository
 * layer while the real Rust message/session pipeline is being reconnected.
 *
 * These types are intentionally dumb byte envelopes. They do not claim to
 * encrypt anything by themselves; cryptographic operations must happen in
 * Rust through QubeeManager once the JNI surface exists again.
 */
data class EncryptedMessage(
    val header: ByteArray = byteArrayOf(),
    val ciphertext: ByteArray,
    val iv: ByteArray = byteArrayOf(),
    val mac: ByteArray = byteArrayOf(),
) {
    fun toBytes(): ByteArray = header + ciphertext + iv + mac

    companion object {
        fun fromBytes(bytes: ByteArray): EncryptedMessage? =
            if (bytes.isEmpty()) null else EncryptedMessage(ciphertext = bytes)
    }
}

data class EncryptedFile(
    val ciphertext: ByteArray,
) {
    fun toBytes(): ByteArray = ciphertext

    companion object {
        fun fromBytes(bytes: ByteArray): EncryptedFile? =
            if (bytes.isEmpty()) null else EncryptedFile(ciphertext = bytes)
    }
}
