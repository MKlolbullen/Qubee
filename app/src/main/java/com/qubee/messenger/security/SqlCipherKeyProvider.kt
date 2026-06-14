package com.qubee.messenger.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import timber.log.Timber

/**
 * Provides the 32-byte symmetric key that opens the SQLCipher-backed
 * `QubeeDatabase`.
 *
 * Wire-up:
 * - On first launch, generate a random 32-byte key and AES-GCM-wrap it
 *   under an Android Keystore master key. The wrapped ciphertext + IV
 *   live in `EncryptedSharedPreferences` (the same backend
 *   `PreferenceRepository` already uses).
 * - On subsequent launches, retrieve and unwrap to the same 32 bytes.
 *
 * Failure policy: **fail closed**. If the Keystore is unavailable or
 * unwrapping fails, [getOrCreate] throws — the caller (Hilt's
 * `provideQubeeDatabase`) is responsible for surfacing that to the
 * user and refusing to open the database. We deliberately do *not*
 * mirror `PreferenceRepository`'s plaintext fallback: that fallback
 * exists for non-secret preferences; the database key is the
 * confidentiality root for the entire local datastore.
 *
 * Migration: the previous build shipped a hardcoded passphrase. This
 * provider exposes [legacyPassphrase] so the database layer can detect
 * a legacy DB file and wipe it before opening under the new key. We
 * deliberately don't implement `PRAGMA rekey` here — the README
 * already states pre-alpha data isn't expected to survive schema
 * changes, and the rekey path requires running raw SQL outside Room's
 * open helper, which is substantially more code.
 */
class SqlCipherKeyProvider(private val context: Context) {

    /**
     * Returns the 32-byte database key, generating and persisting it
     * on first call. Subsequent calls return the same bytes.
     *
     * Throws [SecurityException] if Keystore is unavailable or the
     * stored ciphertext can't be unwrapped (tampering, OS-level key
     * rotation that invalidated the master key, etc.).
     */
    fun getOrCreate(): ByteArray {
        val prefs = openEncryptedPrefs()
            ?: throw SecurityException(
                "Android Keystore unavailable; refusing to open database under unencrypted preferences.",
            )

        val storedCiphertext = prefs.getString(KEY_DB_KEY_CIPHERTEXT, null)
        val storedIv = prefs.getString(KEY_DB_KEY_IV, null)
        if (storedCiphertext != null && storedIv != null) {
            val ciphertext = decodeBase64(storedCiphertext)
            val iv = decodeBase64(storedIv)
            return unwrap(ciphertext, iv)
        }

        // First-launch path: generate, wrap, persist.
        val raw = ByteArray(KEY_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }
        val (ciphertext, iv) = wrap(raw)
        prefs.edit()
            .putString(KEY_DB_KEY_CIPHERTEXT, encodeBase64(ciphertext))
            .putString(KEY_DB_KEY_IV, encodeBase64(iv))
            .apply()
        return raw
    }

    /**
     * Returns the passphrase that protects the Rust core's on-disk
     * keystore (`qubee_keys.db.master` / `qubee_groups.db.master`),
     * which is where the actual Ed25519 + ML-DSA *private identity
     * keys* live. Generated on first call and persisted (wrapped under
     * the same Keystore master key as the DB key), returned verbatim
     * thereafter.
     *
     * This is an **independent** 32-byte random secret — NOT the
     * SQLCipher DB key. Key separation: a compromise of one secret
     * doesn't hand over the other. Returned as a 64-char lowercase
     * hex string because the JNI bridge passes it as a `String`; the
     * Rust side treats the UTF-8 bytes of that hex as the passphrase
     * (it never needs to decode it — it just needs a stable
     * high-entropy byte string).
     *
     * Before this existed, the Rust keystore wrapped its master key
     * under a hardcoded `"default_password"`, meaning the private keys
     * at rest were recoverable by anyone with the files. This closes
     * that hole by binding them to the hardware-backed Keystore.
     *
     * Throws [SecurityException] if the Keystore is unavailable —
     * fail closed, same policy as [getOrCreate].
     */
    fun getOrCreateCoreKeystorePassphrase(): String {
        val prefs = openEncryptedPrefs()
            ?: throw SecurityException(
                "Android Keystore unavailable; refusing to derive core keystore passphrase.",
            )

        val storedCiphertext = prefs.getString(KEY_CORE_PASS_CIPHERTEXT, null)
        val storedIv = prefs.getString(KEY_CORE_PASS_IV, null)
        if (storedCiphertext != null && storedIv != null) {
            val raw = unwrap(decodeBase64(storedCiphertext), decodeBase64(storedIv))
            return raw.toHex()
        }

        val raw = ByteArray(KEY_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }
        val (ciphertext, iv) = wrap(raw)
        prefs.edit()
            .putString(KEY_CORE_PASS_CIPHERTEXT, encodeBase64(ciphertext))
            .putString(KEY_CORE_PASS_IV, encodeBase64(iv))
            .apply()
        return raw.toHex()
    }

    /**
     * Drops the wrapped DB key, the wrapped core-keystore passphrase,
     * and the underlying Keystore master key. Use after a "Reset
     * identity" so the next launch generates fresh secrets (and the
     * existing DB + keystore files should be deleted by the caller
     * before that happens).
     */
    fun clear() {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(MASTER_KEY_ALIAS)) {
                ks.deleteEntry(MASTER_KEY_ALIAS)
            }
        } catch (e: Exception) {
            Timber.w(e, "Failed to delete master key from Android Keystore")
        }
        openEncryptedPrefs()?.edit()
            ?.remove(KEY_DB_KEY_CIPHERTEXT)
            ?.remove(KEY_DB_KEY_IV)
            ?.remove(KEY_CORE_PASS_CIPHERTEXT)
            ?.remove(KEY_CORE_PASS_IV)
            ?.apply()
    }

    private fun ByteArray.toHex(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_DIGITS[v ushr 4])
            sb.append(HEX_DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    /**
     * The hardcoded passphrase shipped before this provider existed.
     * Exposed only so the database layer can detect a legacy DB file
     * and wipe it; nothing else should call this.
     */
    fun legacyPassphrase(): ByteArray =
        LEGACY_PRE_ALPHA_PASSPHRASE.toByteArray(Charsets.UTF_8).copyOf()

    private fun openEncryptedPrefs(): SharedPreferences? = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (e: Exception) {
        Timber.e(e, "EncryptedSharedPreferences unavailable for DB key store")
        null
    }

    private fun wrap(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        val ciphertext = cipher.doFinal(plaintext)
        return ciphertext to cipher.iv
    }

    private fun unwrap(ciphertext: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(
            Cipher.DECRYPT_MODE,
            loadMasterKey() ?: throw SecurityException("Master key missing from Keystore"),
            GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        return cipher.doFinal(ciphertext)
    }

    private fun getOrCreateMasterKey(): SecretKey =
        loadMasterKey() ?: generateMasterKey()

    private fun loadMasterKey(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        return entry?.secretKey
    }

    private fun generateMasterKey(): SecretKey {
        // Try a StrongBox-backed key first (dedicated hardware security
        // module, API 28+). Many devices don't ship StrongBox; on those
        // the init throws StrongBoxUnavailableException and we fall back
        // to a TEE-backed key. Either way the key material never leaves
        // secure hardware — this only affects *which* hardware.
        return try {
            generateMasterKeyInternal(strongBox = true)
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            Timber.d("StrongBox unavailable; falling back to TEE-backed master key")
            // The alias may have been partially created; clear it so the
            // fallback generation under the same alias succeeds.
            runCatching {
                KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                    .takeIf { it.containsAlias(MASTER_KEY_ALIAS) }
                    ?.deleteEntry(MASTER_KEY_ALIAS)
            }
            generateMasterKeyInternal(strongBox = false)
        }
    }

    private fun generateMasterKeyInternal(strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(MASTER_KEY_SIZE_BITS)
            .setRandomizedEncryptionRequired(true)
            // Trade-off: `setUserAuthenticationRequired(false)` lets
            // the headless `MessageService` decrypt the local DB on
            // boot, before the user unlocks the device — which is
            // what allows inbound messages to land in the Room store
            // while the screen is still locked. The downside is that
            // the master key is *only* protected by hardware-backed
            // key custody (StrongBox / TEE) plus system-level access
            // controls; it is not gated behind a biometric / PIN
            // prompt at every DB open.
            //
            // For the alpha threat model (a researcher / developer
            // installing the APK on their own device, where attackers
            // are remote network adversaries rather than a co-located
            // attacker with the unlocked phone in hand) this is the
            // right default. A future "lock-on-screen-off" mode that
            // re-encrypts the in-memory DB key behind biometric
            // unlock is tracked as v0.2+ work.
            .setUserAuthenticationRequired(false)
        if (strongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun encodeBase64(bytes: ByteArray): String =
        android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

    private fun decodeBase64(value: String): ByteArray =
        android.util.Base64.decode(value, android.util.Base64.NO_WRAP)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MASTER_KEY_ALIAS = "qubee_sqlcipher_master_v1"
        private const val PREFS_NAME = "qubee_db_keys.enc"
        private const val KEY_DB_KEY_CIPHERTEXT = "db_key_ciphertext_v1"
        private const val KEY_DB_KEY_IV = "db_key_iv_v1"
        // Separate slots for the Rust core keystore passphrase — an
        // independent secret from the SQLCipher DB key (key separation).
        private const val KEY_CORE_PASS_CIPHERTEXT = "core_pass_ciphertext_v1"
        private const val KEY_CORE_PASS_IV = "core_pass_iv_v1"
        private const val AES_GCM_NO_PADDING = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val MASTER_KEY_SIZE_BITS = 256
        private const val KEY_LENGTH_BYTES = 32
        private const val LEGACY_PRE_ALPHA_PASSPHRASE =
            "qubee-pre-alpha-passphrase-not-secret"
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()
    }
}
