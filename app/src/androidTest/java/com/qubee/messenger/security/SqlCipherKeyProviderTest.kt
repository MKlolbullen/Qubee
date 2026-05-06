package com.qubee.messenger.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented contract test for [SqlCipherKeyProvider].
 *
 * Runs against a real Android Keystore (the JVM-side `KeyStore.getInstance("AndroidKeyStore")`
 * isn't fake-able without Robolectric Shadows; rather than introduce that dependency we exercise
 * the real Keystore on-device).
 *
 * Test plan documented in `docs/two-device-walkthrough.md`. CI doesn't run this until the
 * emulator-access blocker called out in README's roadmap is resolved.
 */
@RunWith(AndroidJUnit4::class)
class SqlCipherKeyProviderTest {

    private lateinit var provider: SqlCipherKeyProvider

    @Before
    fun setUp() {
        provider = SqlCipherKeyProvider(ApplicationProvider.getApplicationContext())
        // Pre-test cleanup: clear() is idempotent, so it's safe to
        // call even on a fresh install.
        provider.clear()
    }

    @After
    fun tearDown() {
        provider.clear()
    }

    @Test
    fun first_call_generates_a_32_byte_key() {
        val key = provider.getOrCreate()
        assertEquals(32, key.size)
        // A randomly-generated 32-byte buffer with all zeros has
        // probability 2^-256; if this fails the SecureRandom is
        // broken.
        assertFalse(key.all { it == 0.toByte() })
    }

    @Test
    fun second_call_returns_the_same_key() {
        val first = provider.getOrCreate()
        val second = provider.getOrCreate()
        assertTrue(first.contentEquals(second))
    }

    @Test
    fun clear_then_get_produces_a_different_key() {
        val first = provider.getOrCreate()
        provider.clear()
        val second = provider.getOrCreate()
        assertEquals(32, second.size)
        // A fresh master key + fresh DB key + fresh IV: collision is
        // a 2^-256 event.
        assertFalse(first.contentEquals(second))
    }

    @Test
    fun legacy_passphrase_is_the_documented_pre_alpha_value() {
        // Locked down so that wipe-on-legacy-detect in QubeeDatabase
        // continues to recognise pre-alpha database files. If this
        // ever changes, every pre-alpha install on the planet would
        // silently get its DB key bumped without the wipe path
        // triggering — the crypto-sensitive symptom is "DB suddenly
        // can't be opened" rather than data loss, but it's still
        // worth pinning.
        val expected = "qubee-pre-alpha-passphrase-not-secret".toByteArray(Charsets.UTF_8)
        val actual = provider.legacyPassphrase()
        assertNotNull(actual)
        assertTrue(actual.contentEquals(expected))
    }
}
