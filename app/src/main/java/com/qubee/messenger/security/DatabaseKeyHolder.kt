package com.qubee.messenger.security

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Process-scoped, in-memory custody of the unwrapped secrets that open
 * the local datastore — the 32-byte SQLCipher database key and the
 * Rust-core keystore passphrase.
 *
 * Only relevant when Screen Lock (app-lock) is on: in that mode the
 * secrets live at rest wrapped under an **auth-bound** Keystore key,
 * so they can't be unwrapped without a fresh biometric / device-
 * credential authentication. The unlock ceremony fills this holder;
 * [SqlCipherKeyProvider.getOrCreate] and the Rust-init path read from
 * it. While it's empty the database cannot be opened — that is the
 * "no DB while locked" property.
 *
 * When Screen Lock is off the holder is unused: the provider unwraps
 * the secrets directly under the auth-free hardware key exactly as
 * before.
 *
 * Not persisted, never logged. Cleared on lock / background so a
 * later foreground has to re-authenticate.
 */
@Singleton
class DatabaseKeyHolder @Inject constructor() {

    private var dbKey: ByteArray? = null
    private var corePassphrase: ByteArray? = null

    val isUnlocked: Boolean
        @Synchronized get() = dbKey != null

    /** Store the unwrapped secrets after a successful unlock. Copies
     *  the inputs so the caller can zero its own buffers. */
    @Synchronized
    fun install(dbKey: ByteArray, corePassphrase: ByteArray) {
        clearLocked()
        this.dbKey = dbKey.copyOf()
        this.corePassphrase = corePassphrase.copyOf()
    }

    /** A fresh copy of the DB key, or null if locked. Caller zeroes it. */
    @Synchronized
    fun dbKeyCopy(): ByteArray? = dbKey?.copyOf()

    /** A fresh copy of the core passphrase, or null if locked. */
    @Synchronized
    fun corePassphraseCopy(): ByteArray? = corePassphrase?.copyOf()

    /** Zero and drop both secrets. Called on lock / background. */
    @Synchronized
    fun clear() = clearLocked()

    private fun clearLocked() {
        dbKey?.fill(0)
        corePassphrase?.fill(0)
        dbKey = null
        corePassphrase = null
    }
}
