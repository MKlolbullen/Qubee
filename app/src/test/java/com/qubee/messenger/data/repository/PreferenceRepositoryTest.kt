package com.qubee.messenger.data.repository

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.ArgumentMatchers.anyString
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class PreferenceRepositoryTest {
    @Test
    fun ratchet_send_defaults_off_and_respects_explicit_opt_in() {
        val context = mock(Context::class.java)
        val prefs = mock(SharedPreferences::class.java)
        `when`(context.applicationContext).thenThrow(SecurityException("Test fallback store"))
        `when`(context.getSharedPreferences(anyString(), eq(Context.MODE_PRIVATE))).thenReturn(prefs)
        `when`(prefs.getBoolean(anyString(), anyBoolean())).thenAnswer { it.getArgument<Boolean>(1) }
        val repository = PreferenceRepository(context)

        assertFalse(repository.ratchetSendEnabled())
        `when`(prefs.getBoolean(eq("ratchet_send_enabled"), anyBoolean())).thenReturn(true)
        assertTrue(repository.ratchetSendEnabled())
        `when`(prefs.getBoolean(eq("ratchet_send_enabled"), anyBoolean())).thenReturn(false)
        assertFalse(repository.ratchetSendEnabled())
    }
}
