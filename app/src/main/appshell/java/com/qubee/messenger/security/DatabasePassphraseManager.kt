package com.qubee.messenger.security

import android.content.Context
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

class DatabasePassphraseManager(
    private val context: Context,
    private val appKeyManager: AppKeyManager,
) {
    companion object {
        private const val PREFS = "qubee_secure_storage"
        private const val KEY_DB_PASSPHRASE = "db_passphrase_envelope"
    }

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun hasWrappedPassphrase(): Boolean = prefs.contains(KEY_DB_PASSPHRASE)

    fun getOrCreatePassphrase(): CharArray {
        val existing = prefs.getString(KEY_DB_PASSPHRASE, null)
        if (existing != null) {
            val plaintext = appKeyManager.decrypt(CipherEnvelope.decodeCompact(existing))
            return plaintext.toString(StandardCharsets.UTF_8).toCharArray().also {
                plaintext.fill(0)
            }
        }

        val raw = ByteArray(32)
        SecureRandom().nextBytes(raw)
        val generated = Base64.encodeToString(raw, Base64.NO_WRAP)
        val envelope = appKeyManager.encrypt(generated.toByteArray(StandardCharsets.UTF_8))
        prefs.edit().putString(KEY_DB_PASSPHRASE, envelope.encodeCompact()).apply()
        raw.fill(0)
        return generated.toCharArray()
    }

    fun wipe() {
        prefs.edit().remove(KEY_DB_PASSPHRASE).apply()
    }
}
