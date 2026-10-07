package com.qubee.messenger.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import java.security.KeyStore
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
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
 * Run by the Android Instrumented Tests workflow on an API 34 emulator.
 * Physical-device process-death and biometric acceptance remain separate.
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
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private fun preferences(): SharedPreferences {
        val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(
            context, "qubee_db_keys.enc", masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    @Test
    fun concurrent_first_open_across_instances_returns_one_secret_per_purpose() {
        val executor = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        try {
            val calls = (0 until 8).map {
                executor.submit(Callable {
                    check(start.await(10, TimeUnit.SECONDS))
                    val instance = SqlCipherKeyProvider(context)
                    instance.getOrCreate() to instance.getOrCreateCoreKeystorePassphrase()
                })
            }
            start.countDown()
            val results = calls.map { it.get(30, TimeUnit.SECONDS) }
            try {
                for ((db, core) in results) {
                    assertArrayEquals(results.first().first, db)
                    assertArrayEquals(results.first().second, core)
                    assertEquals(64, core.size)
                }
                val reopened = SqlCipherKeyProvider(context)
                assertArrayEquals(results.first().first, reopened.getOrCreate())
                assertArrayEquals(results.first().second, reopened.getOrCreateCoreKeystorePassphrase())
            } finally {
                results.forEach { (db, core) -> db.fill(0); core.fill(0) }
            }
        } finally {
            start.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        }
    }

    @Test
    fun incomplete_records_are_never_replaced() {
        for (slot in listOf("db_key", "core_pass", "auth_blob")) {
            for (field in listOf("ciphertext", "iv")) {
                provider.clear()
                val prefs = preferences()
                assertTrue(prefs.edit().putString("${slot}_${field}_v1", "incomplete").commit())
                val before = prefs.all
                val read: () -> Unit = when (slot) {
                    "db_key" -> { { provider.getOrCreate(); Unit } }
                    "core_pass" -> { { provider.getOrCreateCoreKeystorePassphrase(); Unit } }
                    else -> { { provider.isAuthBindingEnabled(); Unit } }
                }
                assertThrows(SecurityException::class.java) { read() }
                assertEquals(before, prefs.all)
            }
        }
    }

    @Test
    fun malformed_record_lengths_and_types_fail_closed() {
        val prefs = preferences()
        assertTrue(prefs.edit()
            .putString("db_key_ciphertext_v1", Base64.encodeToString(ByteArray(47), Base64.NO_WRAP))
            .putString("db_key_iv_v1", Base64.encodeToString(ByteArray(12), Base64.NO_WRAP))
            .commit())
        assertThrows(SecurityException::class.java) { provider.getOrCreate() }
        assertTrue(prefs.edit().putInt("db_key_ciphertext_v1", 1).commit())
        assertThrows(SecurityException::class.java) { provider.getOrCreate() }
    }

    private fun installSyntheticAuthRecord(prefs: SharedPreferences) {
        // Correct envelope sizes, deliberately no authenticated plaintext.
        assertTrue(prefs.edit()
            .putString("auth_blob_ciphertext_v1", Base64.encodeToString(ByteArray(80), Base64.NO_WRAP))
            .putString("auth_blob_iv_v1", Base64.encodeToString(ByteArray(12), Base64.NO_WRAP))
            .commit())
    }

    @Test
    fun auth_bound_state_never_creates_replacement_auth_free_secrets() {
        val prefs = preferences()
        installSyntheticAuthRecord(prefs)
        val before = prefs.all
        assertTrue(provider.isAuthBindingEnabled())
        assertThrows(SecurityException::class.java) { provider.getOrCreate() }
        assertThrows(SecurityException::class.java) { provider.getOrCreateCoreKeystorePassphrase() }
        assertThrows(SecurityException::class.java) { provider.beginUnlock() } // no auth key
        assertEquals(before, prefs.all)
    }

    @Test
    fun conflicting_auth_bound_and_auth_free_state_is_rejected() {
        provider.getOrCreate().fill(0)
        installSyntheticAuthRecord(preferences())
        assertThrows(SecurityException::class.java) { provider.isAuthBindingEnabled() }
        assertThrows(SecurityException::class.java) { provider.getOrCreate() }
    }

    @Test
    fun unavailable_preferences_cannot_disable_auth_binding() {
        val unavailable = SqlCipherKeyProvider(context) { null }
        assertThrows(SecurityException::class.java) { unavailable.isAuthBindingEnabled() }
        assertThrows(SecurityException::class.java) { unavailable.beginUnlock() }
    }

    @Test
    fun missing_master_key_is_not_regenerated_for_another_secret() {
        provider.getOrCreate().fill(0)
        val prefs = preferences()
        val before = prefs.all
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.deleteEntry("qubee_sqlcipher_master_v1")
        assertThrows(SecurityException::class.java) { provider.getOrCreateCoreKeystorePassphrase() }
        assertFalse(keyStore.containsAlias("qubee_sqlcipher_master_v1"))
        assertEquals(before, prefs.all)
    }

    private fun failingPreferences(
        delegate: SharedPreferences,
        publishToMemory: Boolean = false,
        throwOnCommit: Boolean = false,
    ): SharedPreferences = object : SharedPreferences by delegate {
        override fun edit(): SharedPreferences.Editor {
            val editor = delegate.edit()
            return object : SharedPreferences.Editor by editor {
                override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                    editor.putString(key, value)
                    return this
                }
                override fun remove(key: String?): SharedPreferences.Editor {
                    editor.remove(key)
                    return this
                }
                override fun apply() { throw AssertionError("Secret persistence must not use apply()") }
                override fun commit(): Boolean {
                    // Model Android's failed-write/in-memory divergence. This
                    // fake persists too; it tests distrust of the visible map,
                    // not actual disk failure or process-death recovery.
                    if (publishToMemory) check(editor.commit())
                    if (throwOnCommit) throw IllegalStateException("Injected commit failure")
                    return false
                }
            }
        }
    }

    @Test
    fun failed_commit_blocks_retries_even_if_preferences_show_the_value() {
        for (core in listOf(false, true)) {
            provider.clear()
            val prefs = preferences()
            val failing = SqlCipherKeyProvider(context) { failingPreferences(prefs, publishToMemory = true) }
            assertThrows(SecurityException::class.java) {
                if (core) failing.getOrCreateCoreKeystorePassphrase() else failing.getOrCreate()
            }
            assertTrue(prefs.contains(if (core) "core_pass_ciphertext_v1" else "db_key_ciphertext_v1"))
            assertThrows(SecurityException::class.java) { SqlCipherKeyProvider(context).getOrCreate() }
            assertThrows(SecurityException::class.java) { provider.getOrCreateCoreKeystorePassphrase() }
            assertThrows(SecurityException::class.java) { provider.isAuthBindingEnabled() }
            assertThrows(SecurityException::class.java) { provider.beginUnlock() }
        }
    }

    @Test
    fun throwing_commit_also_blocks_other_instances() {
        val prefs = preferences()
        val failing = SqlCipherKeyProvider(context) { failingPreferences(prefs, throwOnCommit = true) }
        assertThrows(IllegalStateException::class.java) { failing.getOrCreate() }
        assertThrows(SecurityException::class.java) { provider.getOrCreate() }
    }

    @Test
    fun failed_clear_preserves_existing_wrapping_key_and_records() {
        provider.getOrCreate().fill(0)
        val prefs = preferences()
        val before = prefs.all
        val failing = SqlCipherKeyProvider(context) { failingPreferences(prefs) }
        assertThrows(SecurityException::class.java) { failing.clear() }
        assertEquals(before, prefs.all)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(keyStore.containsAlias("qubee_sqlcipher_master_v1"))
    }

    @Test
    fun failed_disable_preserves_auth_key_and_holder() {
        val prefs = preferences()
        installSyntheticAuthRecord(prefs)
        // A sentinel proves retirement happens only after the durable write.
        val generator = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore")
        generator.init(android.security.keystore.KeyGenParameterSpec.Builder(
            "qubee_sqlcipher_auth_master_v1",
            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
        ).setBlockModes("GCM").setEncryptionPaddings("NoPadding").setKeySize(256).build())
        generator.generateKey()
        val holder = DatabaseKeyHolder()
        holder.install(ByteArray(32) { 7 }, ByteArray(64) { 'a'.code.toByte() })
        val before = prefs.all
        try {
            val failing = SqlCipherKeyProvider(context) { failingPreferences(prefs) }
            assertThrows(SecurityException::class.java) { failing.disableAuthBinding(holder) }
            assertEquals(before, prefs.all)
            assertTrue(holder.isUnlocked)
            assertTrue(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .containsAlias("qubee_sqlcipher_auth_master_v1"))
        } finally {
            holder.clear()
        }
    }

}
