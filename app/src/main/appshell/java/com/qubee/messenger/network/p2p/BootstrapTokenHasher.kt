package com.qubee.messenger.network.p2p

import java.security.MessageDigest

internal object BootstrapTokenHasher {
    fun hash(token: String): String {
        if (token.isBlank()) return ""
        return MessageDigest.getInstance("SHA-256")
            .digest(token.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    fun hintPrefix(token: String, length: Int = 16): String = hash(token).take(length)
}
