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
class SqlCipherKeyProvider internal constructor(
    private val context: Context,
    private val preferencesFactory: (() -> SharedPreferences?)?,
) {
    constructor(context: Context) : this(context, null)

    // All instances use the same preferences and Keystore aliases. An instance
    // monitor is insufficient when first-open calls come from different owners.
    // Qubee runs these components in one process; this is not a multi-process lock.
    private fun <T> withKeyStoreLock(block: () -> T): T = synchronized(STORE_LOCK) {
        if (persistenceFailed) {
            throw SecurityException("Key persistence failed; restart before accessing secrets.")
        }
        block()
    }

    private fun requireEncryptedPrefs(): SharedPreferences =
        openEncryptedPrefs() ?: throw SecurityException("Encrypted key preferences unavailable.")

    private fun commitOrThrow(editor: SharedPreferences.Editor) {
        // commit() may update the in-memory map even when the disk write fails.
        // Poison access across ALL provider instances until restart or explicit
        // reset, so a retry cannot return a secret that was never persisted.
        persistenceFailed = true
        if (!editor.commit()) throw SecurityException("Could not persist wrapped secrets.")
        persistenceFailed = false
    }

    private fun readWrapped(
        prefs: SharedPreferences,
        ciphertextKey: String,
        ivKey: String,
        plaintextBytes: Int,
    ): Pair<ByteArray, ByteArray>? {
        val hasCiphertext = prefs.contains(ciphertextKey)
        val hasIv = prefs.contains(ivKey)
        if (!hasCiphertext && !hasIv) return null
        if (!hasCiphertext || !hasIv) throw SecurityException("Incomplete wrapped secret record.")
        try {
            val ciphertext = prefs.getString(ciphertextKey, null)
                ?: throw SecurityException("Missing wrapped secret ciphertext.")
            val iv = prefs.getString(ivKey, null)
                ?: throw SecurityException("Missing wrapped secret IV.")
            val ciphertextBytes = plaintextBytes + GCM_TAG_BITS / 8
            if (ciphertext.length != ((ciphertextBytes + 2) / 3) * 4 || iv.length != 16) {
                throw SecurityException("Invalid wrapped secret encoding length.")
            }
            val decodedCiphertext = decodeBase64(ciphertext)
            val decodedIv = decodeBase64(iv)
            if (decodedCiphertext.size != ciphertextBytes || decodedIv.size != 12) {
                throw SecurityException("Invalid wrapped secret length.")
            }
            return decodedCiphertext to decodedIv
        } catch (e: IllegalArgumentException) {
            throw SecurityException("Invalid wrapped secret encoding.", e)
        } catch (e: ClassCastException) {
            throw SecurityException("Invalid wrapped secret record type.", e)
        }
    }

    private fun readAuthBlob(prefs: SharedPreferences): Pair<ByteArray, ByteArray>? {
        val blob = readWrapped(prefs, KEY_AUTH_BLOB_CIPHERTEXT, KEY_AUTH_BLOB_IV, KEY_LENGTH_BYTES * 2)
        if (blob != null && AUTH_FREE_SLOTS.any { prefs.contains(it) }) {
            throw SecurityException("Conflicting auth-bound and auth-free secret records.")
        }
        return blob
    }

    private fun getOrCreateRaw(ciphertextKey: String, ivKey: String): ByteArray {
        val prefs = requireEncryptedPrefs()
        if (readAuthBlob(prefs) != null) {
            throw SecurityException("Secrets are auth-bound; unlock before accessing them.")
        }
        val stored = readWrapped(prefs, ciphertextKey, ivKey, KEY_LENGTH_BYTES)
        if (stored != null) return unwrap(stored.first, stored.second)
        // A missing wrapping key with other persisted secrets is corruption,
        // not permission to replace their only decryption key.
        if (AUTH_FREE_SLOTS.any { prefs.contains(it) } && loadMasterKey() == null) {
            throw SecurityException("Master key missing for existing wrapped secrets.")
        }
        val raw = ByteArray(KEY_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }
        try {
            val (ciphertext, iv) = wrap(raw)
            commitOrThrow(prefs.edit()
                .putString(ciphertextKey, encodeBase64(ciphertext))
                .putString(ivKey, encodeBase64(iv)))
            return raw
        } catch (e: Exception) {
            raw.fill(0)
            throw e
        }
    }


    /**
     * Returns the 32-byte database key, generating and persisting it
     * on first call. Subsequent calls return the same bytes. Creation uses
     * checked synchronous persistence; call from an IO worker, not the UI thread.
     *
     * Throws [SecurityException] if Keystore is unavailable or the
     * stored ciphertext can't be unwrapped (tampering, OS-level key
     * rotation that invalidated the master key, etc.).
     */
    fun getOrCreate(): ByteArray = withKeyStoreLock {
        getOrCreateRaw(KEY_DB_KEY_CIPHERTEXT, KEY_DB_KEY_IV)
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
     * doesn't hand over the other. Returned as the ASCII bytes of the
     * 64-char lowercase hex encoding — byte-identical to the UTF-8 of
     * the hex `String` earlier builds passed over JNI, so existing
     * keystore wraps keep opening. A `ByteArray` rather than a
     * `String` so the caller can zero it after handing it to
     * `nativeInitialize`; JVM strings are immutable and interned, so a
     * `String` passphrase could linger in the heap indefinitely.
     * **Callers must `fill(0)` the returned array when done.**
     *
     * Before this existed, the Rust keystore wrapped its master key
     * under a hardcoded `"default_password"`, meaning the private keys
     * at rest were recoverable by anyone with the files. This binds the wrapping key to Android Keystore. Hardware backing
     * depends on the device/provider and is not assumed by this class.
     *
     * Throws [SecurityException] if the Keystore is unavailable —
     * fail closed, same policy as [getOrCreate].
     */
    fun getOrCreateCoreKeystorePassphrase(): ByteArray = withKeyStoreLock {
        val raw = getOrCreateRaw(KEY_CORE_PASS_CIPHERTEXT, KEY_CORE_PASS_IV)
        try {
            raw.toHexAsciiBytes()
        } finally {
            raw.fill(0)
        }
    }

    // ----- Auth-bound (Screen Lock) binding -------------------------
    //
    // When Screen Lock is enabled the DB key + core passphrase are
    // re-wrapped under a SEPARATE, auth-bound Keystore key
    // (per-use authentication, satisfied only by this app's unlock
    // ceremony via a BiometricPrompt CryptoObject). The auth-free
    // copies are then deleted, so the secrets literally cannot be
    // unwrapped without a fresh biometric / device-credential auth.
    // Both secrets ride one concatenated blob so a single CryptoObject
    // unlocks both.

    /** True when the secrets are stored auth-bound (Screen Lock on). */
    fun isAuthBindingEnabled(): Boolean = withKeyStoreLock {
        readAuthBlob(requireEncryptedPrefs()) != null
    }

    /**
     * Re-wrap the DB key + core passphrase under a fresh auth-bound
     * Keystore key and delete the auth-free copies. Call while the app
     * is unlocked (the auth-free secrets are still readable). Idempotent
     * if already enabled. Throws on Keystore failure — caller reverts
     * the toggle.
     */
    fun enableAuthBinding(holder: DatabaseKeyHolder): Unit = withKeyStoreLock {
        val prefs = requireEncryptedPrefs()
        if (readAuthBlob(prefs) != null) return@withKeyStoreLock

        val dbKey = getOrCreateRaw(KEY_DB_KEY_CIPHERTEXT, KEY_DB_KEY_IV)
        try {
            val coreRaw = getOrCreateRaw(KEY_CORE_PASS_CIPHERTEXT, KEY_CORE_PASS_IV)
            try {
                val blob = dbKey + coreRaw
                try {
                    val authKey = generateAuthBoundKey()
                    val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
                    cipher.init(Cipher.ENCRYPT_MODE, authKey)
                    val ciphertext = cipher.doFinal(blob)
                    commitOrThrow(prefs.edit()
                        .putString(KEY_AUTH_BLOB_CIPHERTEXT, encodeBase64(ciphertext))
                        .putString(KEY_AUTH_BLOB_IV, encodeBase64(cipher.iv))
                        .remove(KEY_DB_KEY_CIPHERTEXT)
                        .remove(KEY_DB_KEY_IV)
                        .remove(KEY_CORE_PASS_CIPHERTEXT)
                        .remove(KEY_CORE_PASS_IV))
                    val coreHex = coreRaw.toHexAsciiBytes()
                    try {
                        holder.install(dbKey, coreHex)
                    } finally {
                        coreHex.fill(0)
                    }
                } finally {
                    blob.fill(0)
                }
            } finally {
                coreRaw.fill(0)
            }
        } finally {
            dbKey.fill(0)
        }
    }

    /** Persist auth-free copies before retiring the auth-bound wrapping key. */
    fun disableAuthBinding(holder: DatabaseKeyHolder): Unit = withKeyStoreLock {
        val prefs = requireEncryptedPrefs()
        if (readAuthBlob(prefs) == null) return@withKeyStoreLock
        val dbKey = holder.dbKeyCopy()
            ?: throw IllegalStateException("Cannot disable app-lock binding while locked.")
        try {
            val coreHex = holder.corePassphraseCopy()
                ?: throw IllegalStateException("Cannot disable app-lock binding while locked.")
            try {
                val coreRaw = hexAsciiToBytes(coreHex)
                try {
                    val (dbCt, dbIv) = wrap(dbKey)
                    val (coreCt, coreIv) = wrap(coreRaw)
                    commitOrThrow(prefs.edit()
                        .putString(KEY_DB_KEY_CIPHERTEXT, encodeBase64(dbCt))
                        .putString(KEY_DB_KEY_IV, encodeBase64(dbIv))
                        .putString(KEY_CORE_PASS_CIPHERTEXT, encodeBase64(coreCt))
                        .putString(KEY_CORE_PASS_IV, encodeBase64(coreIv))
                        .remove(KEY_AUTH_BLOB_CIPHERTEXT)
                        .remove(KEY_AUTH_BLOB_IV))
                    deleteKeystoreEntry(AUTH_MASTER_KEY_ALIAS)
                } finally {
                    coreRaw.fill(0)
                }
            } finally {
                coreHex.fill(0)
            }
        } finally {
            dbKey.fill(0)
        }
    }

    /** Parse 64 ASCII hex chars back into the 32 raw bytes. */
    private fun hexAsciiToBytes(hexAscii: ByteArray): ByteArray {
        require(hexAscii.size == KEY_LENGTH_BYTES * 2) { "Invalid core passphrase length." }
        require(hexAscii.all { Character.digit(it.toInt().toChar(), 16) >= 0 }) {
            "Invalid core passphrase encoding."
        }
        val out = ByteArray(hexAscii.size / 2)
        for (i in out.indices) {
            val hi = Character.digit(hexAscii[i * 2].toInt().toChar(), 16)
            val lo = Character.digit(hexAscii[i * 2 + 1].toInt().toChar(), 16)
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    /**
     * Begin an unlock: returns a [Cipher] initialised for decryption
     * under the auth-bound key (to hand to a [android.hardware.biometrics]
     * `BiometricPrompt.CryptoObject`) paired with the stored ciphertext
     * to feed [completeUnlock] once the prompt authorises it. `null`
     * when binding isn't enabled.
     */
    fun beginUnlock(): UnlockChallenge? = withKeyStoreLock {
        val (ciphertext, iv) = readAuthBlob(requireEncryptedPrefs()) ?: return@withKeyStoreLock null
        val authKey = loadKeystoreKey(AUTH_MASTER_KEY_ALIAS)
            ?: throw SecurityException("Auth-bound key missing from Keystore")
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, authKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        UnlockChallenge(cipher, ciphertext)
    }

    /**
     * Complete an unlock: run the biometric-authorised [cipher] over
     * the stored ciphertext to recover the DB key and core passphrase.
     * The returned [UnlockedSecrets] carries the raw DB key, the raw
     * core secret (for a future [disableAuthBinding]), and the
     * hex-ASCII core passphrase in the form `nativeInitialize` expects.
     */
    fun completeUnlock(challenge: UnlockChallenge): UnlockedSecrets = withKeyStoreLock {
        val current = readAuthBlob(requireEncryptedPrefs())
            ?: throw SecurityException("Auth binding changed during unlock.")
        if (!current.first.contentEquals(challenge.ciphertext)) {
            throw SecurityException("Auth binding changed during unlock.")
        }
        val blob = challenge.cipher.doFinal(challenge.ciphertext)
        try {
            if (blob.size != KEY_LENGTH_BYTES * 2) throw SecurityException("Invalid unlocked secret length.")
            val dbKey = blob.copyOfRange(0, KEY_LENGTH_BYTES)
            val coreRaw = blob.copyOfRange(KEY_LENGTH_BYTES, KEY_LENGTH_BYTES * 2)
            UnlockedSecrets(dbKey, coreRaw, coreRaw.toHexAsciiBytes())
        } finally {
            blob.fill(0)
        }
    }

    data class UnlockChallenge(val cipher: Cipher, val ciphertext: ByteArray)

    data class UnlockedSecrets(
        val dbKey: ByteArray,
        val coreRaw: ByteArray,
        val corePassphraseHex: ByteArray,
    )

    /**
     * Drops the wrapped DB key, the wrapped core-keystore passphrase,
     * and the underlying Keystore master key. Use after a "Reset
     * identity" so the next launch generates fresh secrets (and the
     * existing DB + keystore files should be deleted by the caller
     * before that happens).
     */
    fun clear(): Unit = synchronized(STORE_LOCK) {
        // Explicit reset may recover a failed-write state. Never destroy the
        // only wrapping key before the removal has reached durable storage.
        commitOrThrow(requireEncryptedPrefs().edit()
            .remove(KEY_DB_KEY_CIPHERTEXT)
            .remove(KEY_DB_KEY_IV)
            .remove(KEY_CORE_PASS_CIPHERTEXT)
            .remove(KEY_CORE_PASS_IV)
            .remove(KEY_AUTH_BLOB_CIPHERTEXT)
            .remove(KEY_AUTH_BLOB_IV))
        deleteKeystoreEntry(MASTER_KEY_ALIAS)
        deleteKeystoreEntry(AUTH_MASTER_KEY_ALIAS)
    }

    private fun deleteKeystoreEntry(alias: String) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        } catch (e: Exception) {
            Timber.w(e, "Failed to delete %s from Android Keystore", alias)
        }
    }

    private fun loadKeystoreKey(alias: String): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    /**
     * Generate the auth-bound wrapping key: per-use authentication
     * (`setUserAuthenticationValidityDurationSeconds(-1)` / the
     * API-30+ equivalent), satisfiable by a strong biometric OR the
     * device credential on API 30+. Earlier versions require a strong
     * biometric for a per-use CryptoObject. StrongBox is requested where
     * available; fallback hardware backing is not assumed. Regenerated
     * when binding is enabled (the old key is retired on disable).
     */
    private fun generateAuthBoundKey(): SecretKey {
        deleteKeystoreEntry(AUTH_MASTER_KEY_ALIAS)
        return try {
            generateAuthBoundKeyInternal(strongBox = true)
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            Timber.d("StrongBox unavailable; using default Keystore provider for auth-bound key")
            deleteKeystoreEntry(AUTH_MASTER_KEY_ALIAS)
            generateAuthBoundKeyInternal(strongBox = false)
        }
    }

    private fun generateAuthBoundKeyInternal(strongBox: Boolean): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            AUTH_MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(MASTER_KEY_SIZE_BITS)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            // Per-use (timeout 0), strong biometric OR device credential.
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.init(builder.build())
        return generator.generateKey()
    }

    /**
     * Lowercase-hex encode straight into a `ByteArray` of ASCII codes —
     * deliberately never materialising a `String`, so the only heap
     * copies of the secret are arrays the caller can zero.
     */
    private fun ByteArray.toHexAsciiBytes(): ByteArray {
        val out = ByteArray(size * 2)
        for (i in indices) {
            val v = this[i].toInt() and 0xFF
            out[i * 2] = HEX_DIGITS[v ushr 4].code.toByte()
            out[i * 2 + 1] = HEX_DIGITS[v and 0x0F].code.toByte()
        }
        return out
    }

    /**
     * The hardcoded passphrase shipped before this provider existed.
     * Exposed only so the database layer can detect a legacy DB file
     * and wipe it; nothing else should call this.
     */
    fun legacyPassphrase(): ByteArray =
        LEGACY_PRE_ALPHA_PASSPHRASE.toByteArray(Charsets.UTF_8).copyOf()

    private fun openEncryptedPrefs(): SharedPreferences? = try {
        if (preferencesFactory != null) {
            preferencesFactory.invoke()
        } else {
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
        }
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
        val raw = cipher.doFinal(ciphertext)
        if (raw.size != KEY_LENGTH_BYTES) {
            raw.fill(0)
            throw SecurityException("Invalid unwrapped secret length.")
        }
        return raw
    }

    private fun getOrCreateMasterKey(): SecretKey =
        loadMasterKey() ?: generateMasterKey()

    private fun loadMasterKey(): SecretKey? = loadKeystoreKey(MASTER_KEY_ALIAS)

    private fun generateMasterKey(): SecretKey {
        // Try a StrongBox-backed key first (dedicated hardware security
        // module, API 28+). Many devices don't ship StrongBox; on those
        // the init throws StrongBoxUnavailableException and we fall back
        // to the default provider. This does not prove hardware backing;
        // that requires inspecting KeyInfo on the actual device.
        return try {
            generateMasterKeyInternal(strongBox = true)
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            Timber.d("StrongBox unavailable; using default Keystore provider for master key")
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
            // the master key is protected by Android Keystore
            // key custody (hardware backing varies) plus system-level access
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
        private val STORE_LOCK = Any()
        // Access only while holding STORE_LOCK (including fault-injection tests).
        private var persistenceFailed = false
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MASTER_KEY_ALIAS = "qubee_sqlcipher_master_v1"
        // Auth-bound wrapping key + concatenated (DB key || core
        // passphrase) blob, present only while Screen Lock is on.
        private const val AUTH_MASTER_KEY_ALIAS = "qubee_sqlcipher_auth_master_v1"
        private const val KEY_AUTH_BLOB_CIPHERTEXT = "auth_blob_ciphertext_v1"
        private const val KEY_AUTH_BLOB_IV = "auth_blob_iv_v1"
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
        private val AUTH_FREE_SLOTS = arrayOf(
            KEY_DB_KEY_CIPHERTEXT, KEY_DB_KEY_IV, KEY_CORE_PASS_CIPHERTEXT, KEY_CORE_PASS_IV,
        )
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()
    }
}
