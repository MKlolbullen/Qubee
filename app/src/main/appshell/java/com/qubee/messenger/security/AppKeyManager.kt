package com.qubee.messenger.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AppKeyManager(private val context: Context) {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val APP_MASTER_KEY_ALIAS = "qubee.master.aes.v1"
        private const val AES_MODE = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
    }

    fun hasMasterKey(): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.containsAlias(APP_MASTER_KEY_ALIAS)
    }

    fun getOrCreateMasterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = keyStore.getKey(APP_MASTER_KEY_ALIAS, null)
        if (existing is SecretKey) return existing

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            APP_MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            runCatching { builder.setIsStrongBoxBacked(true) }
        }

        generator.init(builder.build())
        return generator.generateKey()
    }

    fun encrypt(plaintext: ByteArray, aad: ByteArray? = null): CipherEnvelope {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        aad?.let(cipher::updateAAD)
        val ciphertext = cipher.doFinal(plaintext)
        return CipherEnvelope(iv = cipher.iv, ciphertext = ciphertext)
    }

    fun decrypt(envelope: CipherEnvelope, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateMasterKey(),
            GCMParameterSpec(GCM_TAG_BITS, envelope.iv),
        )
        aad?.let(cipher::updateAAD)
        return cipher.doFinal(envelope.ciphertext)
    }

    fun warmUpKeyAccess() {
        // Touch the key after a successful BiometricPrompt flow so SQLCipher passphrase
        // decryption fails early instead of halfway through app initialization.
        encrypt("vault-warmup".toByteArray()).also { decrypt(it).fill(0) }
    }

    fun deleteMasterKey() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(APP_MASTER_KEY_ALIAS)) {
            keyStore.deleteEntry(APP_MASTER_KEY_ALIAS)
        }
    }
}
