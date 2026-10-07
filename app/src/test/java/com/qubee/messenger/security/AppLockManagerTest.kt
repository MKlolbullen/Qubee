package com.qubee.messenger.security

import com.qubee.messenger.data.repository.PreferenceRepository
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class AppLockManagerTest {
    private val preferences = mock(PreferenceRepository::class.java)
    private val keys = mock(SqlCipherKeyProvider::class.java)

    @Test
    fun persisted_binding_locks_even_when_ui_preference_was_not_saved() {
        `when`(preferences.appLockEnabled()).thenReturn(false)
        `when`(keys.isAuthBindingEnabled()).thenReturn(true)
        val manager = AppLockManager(preferences, keys)
        assertTrue(manager.isEnabled())
        assertTrue(manager.locked.value)
        manager.onPreferenceChanged()
        assertTrue(manager.locked.value)
    }

    @Test
    fun unreadable_key_state_keeps_the_gate_closed() {
        `when`(keys.isAuthBindingEnabled()).thenThrow(SecurityException("Unavailable"))
        val manager = AppLockManager(preferences, keys)
        assertTrue(manager.isEnabled())
        assertTrue(manager.locked.value)
        manager.onPreferenceChanged()
        assertTrue(manager.locked.value)
    }

    @Test
    fun legacy_ui_lock_remains_enabled_without_key_binding() {
        `when`(preferences.appLockEnabled()).thenReturn(true)
        `when`(keys.isAuthBindingEnabled()).thenReturn(false)
        assertTrue(AppLockManager(preferences, keys).locked.value)
    }

    @Test
    fun only_readable_unbound_state_with_disabled_preference_starts_unlocked() {
        `when`(preferences.appLockEnabled()).thenReturn(false)
        `when`(keys.isAuthBindingEnabled()).thenReturn(false)
        val manager = AppLockManager(preferences, keys)
        assertFalse(manager.isEnabled())
        assertFalse(manager.locked.value)
    }
}
