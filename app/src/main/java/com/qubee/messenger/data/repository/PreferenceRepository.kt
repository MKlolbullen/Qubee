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
 * Persists local user state (identity bundle, display name) inside an
 * `EncryptedSharedPreferences` file.
 *
 * If the platform refuses to mint a master key (broken Keystore, locked
 * device, hardware-attested key revoked, …) the repository falls back to
 * plain `SharedPreferences` so the app at least remains usable. That
 * fallback is **not** silent: [storageStatus] / [isEncrypted] surface the
 * outcome to callers, and a Timber warning is logged so we can spot it
 * in bug reports / log captures.
 *
 * Callers that handle sensitive material (e.g. anything that survives a
 * full re-onboarding) should check [isEncrypted] before writing, and
 * either prompt the user to retry or refuse to persist on fallback.
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

    /** Convenience boolean for the common "is this safe to write secrets to?" check. */
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
            // Surface the failure loudly: we don't want this to be a silent
            // downgrade in production. Callers that genuinely cannot
            // tolerate plaintext storage should read [isEncrypted] and
            // refuse to persist sensitive bits.
            Timber.w(
                e,
                "EncryptedSharedPreferences unavailable — falling back to plaintext SharedPreferences. " +
                    "Sensitive state should not be stored until the Keystore recovers.",
            )
            val plain = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            OpenResult(plain, StorageStatus.UNENCRYPTED_FALLBACK)
        }
    }

    /**
     * Persist the identity created during onboarding. The hybrid private
     * key never leaves Rust; we only store identifiers + share link here.
     */
    fun saveUserIdentity(userId: String, nickname: String, identityIdHex: String, shareLink: String?) {
        if (!isEncrypted) {
            Timber.w("Persisting onboarding state to UNENCRYPTED_FALLBACK store")
        }
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
        saveUserIdentity(
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

    companion object {
        private const val PREFS_NAME = "qubee_prefs.enc"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_NICKNAME = "nickname"
        private const val KEY_IDENTITY_ID = "identity_id_hex"
        private const val KEY_SHARE_LINK = "share_link"
        private const val KEY_ONBOARDED = "onboarded"
    }
}
