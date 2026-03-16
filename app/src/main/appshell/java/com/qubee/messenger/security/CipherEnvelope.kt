package com.qubee.messenger.security

import android.util.Base64

data class CipherEnvelope(
    val iv: ByteArray,
    val ciphertext: ByteArray,
) {
    fun encodeCompact(): String {
        val ivPart = Base64.encodeToString(iv, Base64.NO_WRAP)
        val cipherPart = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
        return "$ivPart:$cipherPart"
    }

    companion object {
        fun decodeCompact(compact: String): CipherEnvelope {
            val parts = compact.split(':', limit = 2)
            require(parts.size == 2) { "Invalid cipher envelope" }
            return CipherEnvelope(
                iv = Base64.decode(parts[0], Base64.NO_WRAP),
                ciphertext = Base64.decode(parts[1], Base64.NO_WRAP),
            )
        }
    }
}
