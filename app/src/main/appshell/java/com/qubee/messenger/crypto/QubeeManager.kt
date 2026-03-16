package com.qubee.messenger.crypto

import android.util.Base64
import org.json.JSONObject
import java.security.SecureRandom

/**
 * JNI bridge to the Rust `qubee_crypto` native library.
 *
 * Two families of JNI functions:
 *
 * 1. **Legacy** (`nativeXxx`) — raw bytes on success, null on failure.
 * 2. **Result** (`nativeXxxResult`) — JSON envelope:
 *    `{"ok":true,"payloadBase64":"<base64>"}` on success, or
 *    `{"ok":false,"errorCode":"...","errorMessage":"..."}` on failure.
 */
class QubeeManager private constructor() {
    companion object {
        private var libraryLoaded = false
        private var initialized = false

        // ── Library lifecycle ─────────────────────────────────────────────

        fun isLibraryLoaded(): Boolean {
            if (libraryLoaded) return true
            libraryLoaded = runCatching {
                System.loadLibrary("qubee_crypto")
                true
            }.getOrDefault(false)
            return libraryLoaded
        }

        fun isInitialized(): Boolean = initialized

        fun initializeIfPossible(): Boolean {
            if (!isLibraryLoaded()) return false
            initialized = runCatching { nativeInitialize() }.getOrDefault(false)
            return initialized
        }

        // ── Identity ─────────────────────────────────────────────────────

        fun generateIdentityBundleOrNull(
            displayName: String, deviceLabel: String,
            relayHandle: String, deviceId: String,
        ): ByteArray? {
            if (!isReady()) return null
            return runCatching {
                nativeGenerateIdentityBundle(displayName, deviceLabel, relayHandle, deviceId)
            }.getOrNull()
        }

        fun generateIdentityBundle(
            displayName: String, deviceLabel: String,
            relayHandle: String, deviceId: String,
        ): NativeCallResult = wrapResult {
            nativeGenerateIdentityBundleResult(displayName, deviceLabel, relayHandle, deviceId)
        }

        fun restoreIdentityBundleOrNull(identityBundle: ByteArray): Boolean {
            if (!isReady()) return false
            return runCatching { nativeRestoreIdentityBundle(identityBundle) }.getOrDefault(false)
        }

        fun restoreIdentityBundle(identityBundle: ByteArray): NativeCallResult =
            wrapResult { nativeRestoreIdentityBundleResult(identityBundle) }

        // ── Relay authentication ─────────────────────────────────────────

        fun signRelayChallengeOrNull(identityBundle: ByteArray, challenge: ByteArray): ByteArray? {
            if (!isReady()) return null
            return runCatching { nativeSignRelayChallenge(identityBundle, challenge) }.getOrNull()
        }

        fun signRelayChallenge(identityBundle: ByteArray, challenge: ByteArray): NativeCallResult =
            wrapResult { nativeSignRelayChallengeResult(identityBundle, challenge) }

        // ── Session — classical bootstrap ────────────────────────────────

        fun createRatchetSessionOrNull(
            contactId: String, theirPublicKey: ByteArray, isInitiator: Boolean,
        ): ByteArray? {
            if (!isReady()) return null
            return runCatching {
                nativeCreateRatchetSession(contactId, theirPublicKey, isInitiator)
            }.getOrNull()
        }

        fun createRatchetSession(
            contactId: String, theirPublicKey: ByteArray, isInitiator: Boolean,
        ): NativeCallResult = wrapResult {
            nativeCreateRatchetSessionResult(contactId, theirPublicKey, isInitiator)
        }

        // ── Session — hybrid PQ bootstrap ────────────────────────────────

        fun createHybridSessionInitOrNull(
            contactId: String, peerPublicBundle: ByteArray,
        ): ByteArray? {
            if (!isReady()) return null
            return runCatching {
                nativeCreateHybridSessionInit(contactId, peerPublicBundle)
            }.getOrNull()
        }

        fun acceptHybridSessionInitOrNull(
            contactId: String, sessionInit: ByteArray,
        ): ByteArray? {
            if (!isReady()) return null
            return runCatching {
                nativeAcceptHybridSessionInit(contactId, sessionInit)
            }.getOrNull()
        }

        // ── Session — restore / export / rotate / state ──────────────────

        fun restoreSessionBundleOrNull(sessionBundle: ByteArray): Boolean {
            if (!isReady()) return false
            return runCatching { nativeRestoreSessionBundle(sessionBundle) }.getOrDefault(false)
        }

        fun restoreSessionBundle(sessionBundle: ByteArray): NativeCallResult =
            wrapResult { nativeRestoreSessionBundleResult(sessionBundle) }

        fun exportSessionBundle(sessionId: String): NativeCallResult =
            wrapResult { nativeExportSessionBundleResult(sessionId) }

        fun markSessionRekeyRequired(sessionId: String): NativeCallResult =
            wrapResult { nativeMarkSessionRekeyRequiredResult(sessionId) }

        fun markSessionRelinkRequired(sessionId: String): NativeCallResult =
            wrapResult { nativeMarkSessionRelinkRequiredResult(sessionId) }

        fun rotateSessionBundle(
            sessionId: String, peerPublicBundle: ByteArray, isInitiator: Boolean,
        ): NativeCallResult = wrapResult {
            nativeRotateSessionBundleResult(sessionId, peerPublicBundle, isInitiator)
        }

        // ── Encrypt / Decrypt ────────────────────────────────────────────

        fun encryptMessageOrNull(sessionId: String, plaintext: ByteArray): ByteArray? {
            if (!isReady()) return null
            return runCatching { nativeEncryptMessage(sessionId, plaintext) }.getOrNull()
        }

        fun encryptMessage(sessionId: String, plaintext: ByteArray): NativeCallResult =
            wrapResult { nativeEncryptMessageResult(sessionId, plaintext) }

        fun decryptMessageOrNull(sessionId: String, ciphertext: ByteArray): ByteArray? {
            if (!isReady()) return null
            return runCatching { nativeDecryptMessage(sessionId, ciphertext) }.getOrNull()
        }

        fun decryptMessage(sessionId: String, ciphertext: ByteArray): NativeCallResult =
            wrapResult { nativeDecryptMessageResult(sessionId, ciphertext) }

        // ── Invite / Safety code ─────────────────────────────────────────

        fun exportInvitePayloadOrNull(identityBundle: ByteArray): ByteArray? {
            if (!isReady()) return null
            return runCatching { nativeExportInvitePayload(identityBundle) }.getOrNull()
        }

        fun inspectInvitePayloadOrNull(invitePayload: ByteArray): ByteArray? {
            if (!isReady()) return null
            return runCatching { nativeInspectInvitePayload(invitePayload) }.getOrNull()
        }

        fun computeSafetyCodeOrNull(
            identityBundle: ByteArray, peerPublicBundle: ByteArray,
        ): ByteArray? {
            if (!isReady()) return null
            return runCatching {
                nativeComputeSafetyCode(identityBundle, peerPublicBundle)
            }.getOrNull()
        }

        // ── Cleanup ──────────────────────────────────────────────────────

        fun cleanup() {
            if (!isLibraryLoaded()) return
            runCatching { nativeCleanup() }
            initialized = false
        }

        fun mockIdentityBytes(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        // ── Internal helpers ─────────────────────────────────────────────

        private fun isReady(): Boolean = isLibraryLoaded() && initialized

        private inline fun wrapResult(block: () -> ByteArray?): NativeCallResult {
            if (!isReady()) return NativeCallResult.notReady()
            return parseResult(runCatching { block() }.getOrNull())
        }

        private fun parseResult(raw: ByteArray?): NativeCallResult {
            if (raw == null || raw.isEmpty()) {
                return NativeCallResult(
                    ok = false, errorCode = "jni_null",
                    errorMessage = "JNI returned null",
                )
            }
            return try {
                val json = JSONObject(String(raw, Charsets.UTF_8))
                NativeCallResult(
                    ok = json.optBoolean("ok", false),
                    errorCode = json.optString("errorCode").takeIf { it.isNotBlank() },
                    errorMessage = json.optString("errorMessage").takeIf { it.isNotBlank() },
                    payloadBase64 = json.optString("payloadBase64").takeIf { it.isNotBlank() },
                )
            } catch (e: Exception) {
                NativeCallResult(
                    ok = false, errorCode = "json_parse_failed",
                    errorMessage = "Failed to parse native result: ${e.message}",
                )
            }
        }

        // ══════════════════════════════════════════════════════════════════
        //  Native declarations — must match jni_api.rs exports exactly
        // ══════════════════════════════════════════════════════════════════

        // Lifecycle
        @JvmStatic private external fun nativeInitialize(): Boolean
        @JvmStatic private external fun nativeCleanup()

        // Identity — legacy
        @JvmStatic private external fun nativeGenerateIdentityBundle(
            displayName: String, deviceLabel: String,
            relayHandle: String, deviceId: String,
        ): ByteArray?
        @JvmStatic private external fun nativeRestoreIdentityBundle(identityBundle: ByteArray): Boolean
        // Identity — result
        @JvmStatic private external fun nativeGenerateIdentityBundleResult(
            displayName: String, deviceLabel: String,
            relayHandle: String, deviceId: String,
        ): ByteArray?
        @JvmStatic private external fun nativeRestoreIdentityBundleResult(identityBundle: ByteArray): ByteArray?

        // Relay auth — legacy + result
        @JvmStatic private external fun nativeSignRelayChallenge(identityBundle: ByteArray, challenge: ByteArray): ByteArray?
        @JvmStatic private external fun nativeSignRelayChallengeResult(identityBundle: ByteArray, challenge: ByteArray): ByteArray?

        // Session — legacy
        @JvmStatic private external fun nativeCreateRatchetSession(contactId: String, theirPublicKey: ByteArray, isInitiator: Boolean): ByteArray?
        @JvmStatic private external fun nativeRestoreSessionBundle(sessionBundle: ByteArray): Boolean
        @JvmStatic private external fun nativeEncryptMessage(sessionId: String, plaintext: ByteArray): ByteArray?
        @JvmStatic private external fun nativeDecryptMessage(sessionId: String, ciphertext: ByteArray): ByteArray?

        // Session — result
        @JvmStatic private external fun nativeCreateRatchetSessionResult(contactId: String, theirPublicKey: ByteArray, isInitiator: Boolean): ByteArray?
        @JvmStatic private external fun nativeRestoreSessionBundleResult(sessionBundle: ByteArray): ByteArray?
        @JvmStatic private external fun nativeExportSessionBundleResult(sessionId: String): ByteArray?
        @JvmStatic private external fun nativeMarkSessionRekeyRequiredResult(sessionId: String): ByteArray?
        @JvmStatic private external fun nativeMarkSessionRelinkRequiredResult(sessionId: String): ByteArray?
        @JvmStatic private external fun nativeRotateSessionBundleResult(sessionId: String, peerPublicBundle: ByteArray, isInitiator: Boolean): ByteArray?
        @JvmStatic private external fun nativeEncryptMessageResult(sessionId: String, plaintext: ByteArray): ByteArray?
        @JvmStatic private external fun nativeDecryptMessageResult(sessionId: String, ciphertext: ByteArray): ByteArray?

        // Hybrid PQ bootstrap
        @JvmStatic private external fun nativeCreateHybridSessionInit(contactId: String, peerPublicBundle: ByteArray): ByteArray?
        @JvmStatic private external fun nativeAcceptHybridSessionInit(contactId: String, sessionInit: ByteArray): ByteArray?

        // Invite / safety code
        @JvmStatic private external fun nativeExportInvitePayload(identityBundle: ByteArray): ByteArray?
        @JvmStatic private external fun nativeInspectInvitePayload(invitePayload: ByteArray): ByteArray?
        @JvmStatic private external fun nativeComputeSafetyCode(identityBundle: ByteArray, peerPublicBundle: ByteArray): ByteArray?
    }
}

/**
 * Structured result from `*Result` JNI calls.
 * Matches Rust `NativeCallResult` JSON envelope.
 */
data class NativeCallResult(
    val ok: Boolean,
    val errorCode: String? = null,
    val errorMessage: String? = null,
    val payloadBase64: String? = null,
) {
    fun payloadOrNull(): ByteArray? {
        if (!ok || payloadBase64.isNullOrBlank()) return null
        return try { Base64.decode(payloadBase64, Base64.NO_WRAP) } catch (_: Exception) { null }
    }

    fun isOkEmpty(): Boolean = ok && payloadBase64.isNullOrBlank()

    companion object {
        fun notReady() = NativeCallResult(
            ok = false, errorCode = "not_ready",
            errorMessage = "Native library not loaded or not initialized",
        )
    }
}
