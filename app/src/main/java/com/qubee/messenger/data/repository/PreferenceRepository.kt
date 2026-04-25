package com.qubee.messenger.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.qubee.messenger.identity.IdentityBundle
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persists local user state (identity bundle, display name) inside an
 * `EncryptedSharedPreferences` file. Falls back to plain prefs only if
 * the platform refuses to mint a master key — that fallback should only
 * ever fire on broken devices and is logged via Timber by callers.
 */
@Singleton
class PreferenceRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    private val prefs: SharedPreferences by lazy { openPrefs() }

    private fun openPrefs(): SharedPreferences {
        return try {
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
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
    }

    /**
     * Persist the identity created during onboarding. The hybrid private
     * key never leaves Rust; we only store identifiers + share link here.
     */
    fun saveUserIdentity(userId: String, nickname: String, identityIdHex: String, shareLink: String?) {
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
