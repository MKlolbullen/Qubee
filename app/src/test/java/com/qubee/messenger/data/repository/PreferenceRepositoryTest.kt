package com.qubee.messenger.data.repository

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.ArgumentMatchers.anyBoolean
import org.mockito.ArgumentMatchers.anyString
import org.mockito.ArgumentMatchers.eq
import org.mockito.ArgumentMatchers.isNull
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

    @Test
    fun discovery_defaults_to_off_with_no_bootstrap_peers() {
        val context = mock(Context::class.java)
        val prefs = mock(SharedPreferences::class.java)
        `when`(context.applicationContext).thenThrow(SecurityException("Test fallback store"))
        `when`(context.getSharedPreferences(anyString(), eq(Context.MODE_PRIVATE))).thenReturn(prefs)
        `when`(prefs.getBoolean(anyString(), anyBoolean())).thenAnswer { it.getArgument<Boolean>(1) }
        val repository = PreferenceRepository(context)

        assertFalse(repository.lanDiscoveryEnabled())
        assertEquals("", repository.bootstrapPeers())

        val peer = "/ip4/192.168.1.20/tcp/4001/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"
        `when`(prefs.getString(eq("bootstrap_peers"), isNull())).thenReturn(peer)
        assertEquals(peer, repository.bootstrapPeers())
        `when`(prefs.getBoolean(eq("lan_discovery_enabled"), anyBoolean())).thenReturn(true)
        assertTrue(repository.lanDiscoveryEnabled())
    }
}
