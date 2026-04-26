package com.qubee.messenger.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.qubee.messenger.identity.IdentityBundle
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import timber.log.Timber

/**
 * Persists local user state inside an `EncryptedSharedPreferences` file.
 *
 * The store is split into two tiers by sensitivity:
 *
 * * **Public metadata** — user id, display name, identity hash,
 *   `qubee://identity/...` share link. None of these are secrets (the
 *   identity hash is `BLAKE3(public_key)` by construction; the share
 *   link is a hybrid-signature-protected bundle that anyone can verify
 *   from the advertised public key). [savePublicMetadata] /
 *   [saveBundle] persist these in either tier.
 * * **Secrets** — anything that genuinely needs confidentiality at
 *   rest. [saveSecret] refuses to write when the backing store fell
 *   back to plaintext, returning `false` so the caller can decide what
 *   to do (prompt the user, retry, surface an error).
 *
 * Real cryptographic material (Dilithium/Kyber/Ed25519 private keys)
 * lives in the Rust core's own secure keystore and never touches this
 * class — the secret tier here exists for future Kotlin-side state
 * that needs the same protection.
 */
@Singleton
class PreferenceRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /** Whether the on-disk store is actually encrypted at rest. */
    enum class StorageStatus {
        /** EncryptedSharedPreferences with an AES256_GCM master key. */
        ENCRYPTED,
        /** Plain SharedPreferences — only ever reached after a Keystore failure. */
        UNENCRYPTED_FALLBACK,
    }

    private val opened: OpenResult by lazy { openPrefs() }

    /** Snapshot of the current storage backend. */
    val storageStatus: StorageStatus get() = opened.status

    /** Convenience boolean for the "is this safe to write secrets to?" check. */
    val isEncrypted: Boolean get() = storageStatus == StorageStatus.ENCRYPTED

    private val prefs: SharedPreferences get() = opened.prefs

    private data class OpenResult(val prefs: SharedPreferences, val status: StorageStatus)

    private fun openPrefs(): OpenResult {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val encrypted = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            OpenResult(encrypted, StorageStatus.ENCRYPTED)
        } catch (e: Exception) {
            // One-time loud warning at open time. We don't repeat per-write
            // for public-tier data — that would be cargo-cult noise — but
            // saveSecret() refuses outright in this state.
            Timber.w(
                e,
                "EncryptedSharedPreferences unavailable — falling back to plaintext SharedPreferences. " +
                    "Public metadata still persists; secret-tier writes will be refused.",
            )
            val plain = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            OpenResult(plain, StorageStatus.UNENCRYPTED_FALLBACK)
        }
    }

    // -------- Public metadata tier (always succeeds) --------

    /**
     * Persist non-secret onboarding state. Safe to call regardless of
     * [storageStatus]; the values are public by construction.
     */
    fun savePublicMetadata(
        userId: String,
        nickname: String,
        identityIdHex: String,
        shareLink: String?,
    ) {
        prefs.edit()
            .putString(KEY_USER_ID, userId)
            .putString(KEY_NICKNAME, nickname)
            .putString(KEY_IDENTITY_ID, identityIdHex)
            .putString(KEY_SHARE_LINK, shareLink)
            .putBoolean(KEY_ONBOARDED, true)
            .apply()
    }

    /** Convenience that mirrors the JSON envelope returned from Rust. */
    fun saveBundle(bundle: IdentityBundle) {
        savePublicMetadata(
            userId = bundle.userId,
            nickname = bundle.displayName,
            identityIdHex = bundle.identityIdHex,
            shareLink = bundle.shareLink,
        )
    }

    fun isOnboarded(): Boolean = prefs.getBoolean(KEY_ONBOARDED, false)

    fun nickname(): String? = prefs.getString(KEY_NICKNAME, null)
    fun userId(): String? = prefs.getString(KEY_USER_ID, null)
    fun identityIdHex(): String? = prefs.getString(KEY_IDENTITY_ID, null)
    fun shareLink(): String? = prefs.getString(KEY_SHARE_LINK, null)

    // -------- Secret tier (gated by isEncrypted) --------

    /**
     * Persist a value that genuinely needs confidentiality at rest.
     * Returns `true` on success, `false` if the backing store is the
     * unencrypted fallback — in which case nothing is written and the
     * caller must decide policy (prompt the user, surface an error,
     * retry once Keystore recovers, …).
     */
    fun saveSecret(key: String, value: String): Boolean {
        if (!isEncrypted) {
            Timber.w("Refusing to write secret %s to %s store", key, storageStatus)
            return false
        }
        prefs.edit().putString(secretKey(key), value).apply()
        return true
    }

    /** Read a secret-tier value. Available regardless of tier so existing
     *  data isn't orphaned if the Keystore is later restored. */
    fun readSecret(key: String): String? = prefs.getString(secretKey(key), null)

    /** Remove a secret-tier value. Always succeeds. */
    fun clearSecret(key: String) {
        prefs.edit().remove(secretKey(key)).apply()
    }

    /**
     * Wipe everything we persist — public metadata, secrets, the
     * onboarded flag. Used by Settings → "Reset identity" alongside
     * the JNI keystore wipe; after this `isOnboarded()` returns false
     * and the next launch routes through onboarding again.
     */
    fun clearAll() {
        prefs.edit().clear().apply()
    }

    private fun secretKey(key: String): String = "$KEY_SECRET_PREFIX$key"

    companion object {
        private const val PREFS_NAME = "qubee_prefs.enc"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_NICKNAME = "nickname"
        private const val KEY_IDENTITY_ID = "identity_id_hex"
        private const val KEY_SHARE_LINK = "share_link"
        private const val KEY_ONBOARDED = "onboarded"
        private const val KEY_SECRET_PREFIX = "secret/"
    }
}
