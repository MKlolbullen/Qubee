package com.qubee.messenger.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for the in-memory key custody. The auth-bound Keystore
 * path can only be exercised on a real device (hardware-backed keys +
 * BiometricPrompt), so this pins the holder's own contract: copies in,
 * copies out, and a genuine wipe on clear.
 */
class DatabaseKeyHolderTest {

    @Test
    fun starts_locked() {
        assertFalse(DatabaseKeyHolder().isUnlocked)
        assertNull(DatabaseKeyHolder().dbKeyCopy())
        assertNull(DatabaseKeyHolder().corePassphraseCopy())
    }

    @Test
    fun install_then_read_returns_equal_but_distinct_copies() {
        val holder = DatabaseKeyHolder()
        val dbKey = ByteArray(32) { it.toByte() }
        val core = ByteArray(64) { (it + 1).toByte() }

        holder.install(dbKey, core)
        assertTrue(holder.isUnlocked)

        val outDb = holder.dbKeyCopy()!!
        val outCore = holder.corePassphraseCopy()!!
        assertArrayEquals(dbKey, outDb)
        assertArrayEquals(core, outCore)

        // Mutating the caller's buffers or the returned copies must not
        // affect the holder's stored secret.
        dbKey.fill(0)
        outDb.fill(0x7F)
        assertArrayEquals(ByteArray(32) { it.toByte() }, holder.dbKeyCopy())
    }

    @Test
    fun clear_wipes_and_locks() {
        val holder = DatabaseKeyHolder()
        holder.install(ByteArray(32) { 9 }, ByteArray(64) { 9 })
        holder.clear()
        assertFalse(holder.isUnlocked)
        assertNull(holder.dbKeyCopy())
        assertNull(holder.corePassphraseCopy())
    }

    @Test
    fun reinstall_replaces_previous_secret() {
        val holder = DatabaseKeyHolder()
        holder.install(ByteArray(32) { 1 }, ByteArray(64) { 1 })
        holder.install(ByteArray(32) { 2 }, ByteArray(64) { 2 })
        assertArrayEquals(ByteArray(32) { 2 }, holder.dbKeyCopy())
        assertArrayEquals(ByteArray(64) { 2 }, holder.corePassphraseCopy())
    }
}
