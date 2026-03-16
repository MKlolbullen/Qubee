package com.qubee.messenger.crypto

import android.util.Base64
import com.qubee.messenger.model.InvitePreview
import com.qubee.messenger.model.InviteShareBundle
import com.qubee.messenger.model.NativeAvailability
import com.qubee.messenger.model.NativeBridgeStatus
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class RelayCryptoEngine : CryptoEngine {
    private val random = SecureRandom()

    override fun status(): NativeBridgeStatus {
        val loaded = QubeeManager.isLibraryLoaded()
        val initialized = QubeeManager.isInitialized()
        return when {
            initialized -> NativeBridgeStatus(NativeAvailability.Ready, "Native library loaded and initialized. Hybrid PQ bootstrap and relay signatures are available.")
            loaded -> NativeBridgeStatus(NativeAvailability.Unavailable, "Native library is packaged but not initialized. Secure messaging should stay locked until initialization succeeds.")
            else -> NativeBridgeStatus(
                NativeAvailability.FallbackMock,
                "Native library not packaged yet. Shell mode is preview-only and relay authentication stays disabled."
            )
        }
    }

    override fun initializeIfPossible(): NativeBridgeStatus {
        QubeeManager.initializeIfPossible()
        return status()
    }

    override fun createIdentity(displayName: String): IdentityMaterial {
        initializeIfPossible()
        val relayHandle = displayName.trim().lowercase().replace(" ", ".") + "@qubee.local"
        val deviceId = "android-" + UUID.randomUUID().toString().substring(0, 8)
        val nativePayload = QubeeManager.generateIdentityBundleOrNull(
            displayName = displayName,
            deviceLabel = "Android device",
            relayHandle = relayHandle,
            deviceId = deviceId,
        )
        if (nativePayload != null && nativePayload.isNotEmpty()) {
            return parseIdentityMaterial(nativePayload, nativeBacked = true)
        }

        val fallbackBundleBytes = fallbackIdentityBundle(displayName, relayHandle, deviceId)
        return parseIdentityMaterial(fallbackBundleBytes, nativeBacked = false)
    }

    override fun restoreIdentity(identity: IdentityMaterial): Boolean {
        initializeIfPossible()
        if (!identity.nativeBacked) return false
        return QubeeManager.restoreIdentityBundleOrNull(decode(identity.identityBundleBase64))
    }

    override fun signRelayChallenge(identity: IdentityMaterial, challenge: String, relaySessionId: String): String? {
        val payload = "$relaySessionId:$challenge".toByteArray(StandardCharsets.UTF_8)
        if (identity.nativeBacked) {
            val signed = QubeeManager.signRelayChallengeOrNull(decode(identity.identityBundleBase64), payload)
            if (signed != null && signed.isNotEmpty()) {
                return Base64.encodeToString(signed, Base64.NO_WRAP)
            }
            return null
        }
        return null
    }

    override fun exportInvite(identity: IdentityMaterial): InviteShareBundle {
        initializeIfPossible()
        val inviteBytes = if (identity.nativeBacked) {
            QubeeManager.exportInvitePayloadOrNull(decode(identity.identityBundleBase64))
        } else null
        val normalized = inviteBytes ?: fallbackInvitePayload(identity)
        val payloadText = INVITE_PREFIX + Base64.encodeToString(normalized, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val bootstrapToken = deriveBootstrapToken(identity.relayHandle, identity.deviceId, identity.identityFingerprint)
        return InviteShareBundle(
            payloadText = payloadText,
            relayHandle = identity.relayHandle,
            identityFingerprint = identity.identityFingerprint,
            shareLabel = "QR-ready invite payload",
            bootstrapToken = bootstrapToken,
            preferredBootstrap = "wifi-direct+ble",
            turnHint = "relay-assisted-turn",
        )
    }

    override fun inspectInvitePayload(payloadText: String): InvitePreview {
        initializeIfPossible()
        val rawBytes = normalizeInvitePayload(payloadText)
        val inspected = QubeeManager.inspectInvitePayloadOrNull(rawBytes) ?: rawBytes
        val json = JSONObject(String(inspected, StandardCharsets.UTF_8))
        val relayHandle = json.getString("relayHandle")
        val deviceId = json.optString("deviceId", "unknown-device")
        val fingerprint = json.getString("identityFingerprint")
        return InvitePreview(
            displayName = json.optString("displayName", "Unknown contact"),
            relayHandle = relayHandle,
            deviceId = deviceId,
            identityFingerprint = fingerprint,
            publicBundleBase64 = json.getString("publicBundleBase64"),
            bootstrapToken = json.optString("bootstrapToken").takeIf { it.isNotBlank() } ?: deriveBootstrapToken(relayHandle, deviceId, fingerprint),
            preferredBootstrap = json.optString("preferredBootstrap", "wifi-direct+ble"),
            turnHint = json.optString("turnHint", "relay-assisted-turn"),
        )
    }

    override fun computeSafetyCode(identity: IdentityMaterial, peerPublicBundleBase64: String): String {
        initializeIfPossible()
        if (identity.nativeBacked) {
            val result = QubeeManager.computeSafetyCodeOrNull(
                decode(identity.identityBundleBase64),
                decode(peerPublicBundleBase64),
            )
            if (result != null && result.isNotEmpty()) {
                return String(result, StandardCharsets.UTF_8)
            }
        }

        val selfBytes = decode(identity.publicBundleBase64)
        val peerBytes = decode(peerPublicBundleBase64)
        val ordered = listOf(selfBytes, peerBytes).sortedBy { Base64.encodeToString(it, Base64.NO_WRAP) }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(ordered[0] + ordered[1])
        return digest
            .take(8)
            .joinToString("") { "%02x".format(it) }
            .chunked(4)
            .joinToString(" ")
    }

    override fun createSession(
        conversationId: String,
        peerHandle: String,
        selfPublicBundleBase64: String,
        peerPublicBundleBase64: String,
    ): SessionMaterial {
        initializeIfPossible()
        val peerBytes = decode(peerPublicBundleBase64)
        val hybridResult = QubeeManager.createHybridSessionInitOrNull(peerHandle, peerBytes)
        if (hybridResult != null && hybridResult.isNotEmpty()) {
            return parseSessionCreationResult(conversationId, peerHandle, hybridResult, nativeBacked = true)
        }
        throw IllegalStateException(
            "Native hybrid session bootstrap is required for trusted messaging. Preview-shell fallback is disabled."
        )
    }

    override fun acceptSessionBootstrap(
        conversationId: String,
        peerHandle: String,
        bootstrapPayloadBase64: String,
    ): SessionMaterial? {
        initializeIfPossible()
        val accepted = QubeeManager.acceptHybridSessionInitOrNull(peerHandle, decode(bootstrapPayloadBase64)) ?: return null
        if (accepted.isEmpty()) return null
        return parseSessionMaterial(conversationId, peerHandle, accepted, nativeBacked = true)
    }

    override fun encryptMessage(session: SessionMaterial, plaintext: String): EncryptedPayload {
        require(session.nativeBacked) {
            "Preview-shell session cannot send trusted messages. Native hybrid messaging is required."
        }
        val utf8 = plaintext.toByteArray(StandardCharsets.UTF_8)
        val nativeCipher = QubeeManager.encryptMessageOrNull(session.sessionId, utf8)
            ?: throw IllegalStateException("Native encrypt failed for session ${session.sessionId}")
        require(nativeCipher.isNotEmpty()) { "Native encrypt produced an empty ciphertext envelope" }
        return EncryptedPayload(
            ciphertextBase64 = Base64.encodeToString(nativeCipher, Base64.NO_WRAP),
            algorithm = "native-json-envelope"
        )
    }

    override fun decryptMessage(session: SessionMaterial, payload: EncryptedPayload): String {
        require(session.nativeBacked) {
            "Preview-shell session cannot decrypt trusted messages. Native hybrid messaging is required."
        }
        require(payload.algorithm == "native-json-envelope") {
            "Unexpected payload algorithm ${payload.algorithm}; only native JSON envelopes are accepted."
        }
        val nativeResult = QubeeManager.decryptMessageOrNull(session.sessionId, decode(payload.ciphertextBase64))
            ?: throw IllegalStateException("Native decrypt failed for session ${session.sessionId}")
        require(nativeResult.isNotEmpty()) { "Native decrypt produced an empty plaintext" }
        return String(nativeResult, StandardCharsets.UTF_8)
    }

    override fun generateDemoPeerBundle(seed: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(seed.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(
            JSONObject()
                .put("schema", "qubee.public.bundle.v1")
                .put("identityFingerprint", digest.take(8).joinToString("") { "%02x".format(it) })
                .put("relayHandle", "$seed@qubee.local")
                .put("deviceId", "demo-$seed")
                .put("dhPublicKeyBase64", Base64.encodeToString(digest.copyOfRange(0, 16), Base64.NO_WRAP))
                .put("signingPublicKeyBase64", Base64.encodeToString(digest.copyOfRange(16, 32), Base64.NO_WRAP))
                .toString()
                .toByteArray(StandardCharsets.UTF_8),
            Base64.NO_WRAP,
        )
    }

    private fun parseIdentityMaterial(bytes: ByteArray, nativeBacked: Boolean): IdentityMaterial {
        val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
        return IdentityMaterial(
            displayName = json.optString("displayName", "Victor"),
            deviceLabel = json.optString("deviceLabel", "Android device"),
            identityFingerprint = json.getString("identityFingerprint"),
            publicBundleBase64 = json.getString("publicBundleBase64"),
            identityBundleBase64 = Base64.encodeToString(bytes, Base64.NO_WRAP),
            relayHandle = json.getString("relayHandle"),
            deviceId = json.getString("deviceId"),
            nativeBacked = nativeBacked,
        )
    }

    private fun parseSessionCreationResult(
        conversationId: String,
        peerHandle: String,
        bytes: ByteArray,
        nativeBacked: Boolean,
    ): SessionMaterial {
        val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
        return if (json.optString("schema").startsWith("qubee.session.init.v")) {
            val sessionBundle = decode(json.getString("sessionBundleBase64"))
            parseSessionMaterial(
                conversationId = conversationId,
                peerHandle = peerHandle,
                bytes = sessionBundle,
                nativeBacked = nativeBacked,
                bootstrapPayloadBase64 = Base64.encodeToString(bytes, Base64.NO_WRAP),
            )
        } else {
            parseSessionMaterial(
                conversationId = conversationId,
                peerHandle = peerHandle,
                bytes = bytes,
                nativeBacked = nativeBacked,
            )
        }
    }

    private fun parseSessionMaterial(
        conversationId: String,
        peerHandle: String,
        bytes: ByteArray,
        nativeBacked: Boolean,
        bootstrapPayloadBase64: String? = null,
    ): SessionMaterial {
        val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
        // Store the full session bundle bytes so Rust can be restored from them after app restart
        val fullBundleBase64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
        return SessionMaterial(
            conversationId = conversationId,
            sessionId = json.optString("sessionId", peerHandle),
            peerHandle = json.optString("peerHandle", peerHandle),
            keyMaterialBase64 = fullBundleBase64,
            nativeBacked = nativeBacked,
            state = json.optString("state", if (nativeBacked) "NativeActive" else "ShellActive"),
            bootstrapPayloadBase64 = bootstrapPayloadBase64 ?: json.optString("bootstrapPayloadBase64").takeIf { it.isNotBlank() },
            algorithm = json.optString("algorithm").takeIf { it.isNotBlank() }
                ?: if (nativeBacked) "ml-kem-768+x25519+chacha20poly1305" else "preview-shell-aes-gcm",
        )
    }

    private fun fallbackIdentityBundle(displayName: String, relayHandle: String, deviceId: String): ByteArray {
        val identityBytes = ByteArray(32).also(random::nextBytes)
        val publicBytes = MessageDigest.getInstance("SHA-256").digest(identityBytes)
        val fingerprint = publicBytes.take(8).joinToString("") { "%02x".format(it) }.chunked(4).joinToString(" ")
        val publicBundleJson = JSONObject()
            .put("schema", "qubee.public.bundle.v1")
            .put("identityFingerprint", fingerprint)
            .put("relayHandle", relayHandle)
            .put("deviceId", deviceId)
            .put("dhPublicKeyBase64", Base64.encodeToString(publicBytes.copyOfRange(0, 16), Base64.NO_WRAP))
            .put("signingPublicKeyBase64", Base64.encodeToString(publicBytes.copyOfRange(16, 32), Base64.NO_WRAP))
            .toString()
        return JSONObject()
            .put("schema", "qubee.identity.bundle.v1")
            .put("displayName", displayName)
            .put("deviceLabel", "Android device")
            .put("identityFingerprint", fingerprint)
            .put("relayHandle", relayHandle)
            .put("deviceId", deviceId)
            .put("publicBundleBase64", Base64.encodeToString(publicBundleJson.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP))
            .put("createdAt", System.currentTimeMillis())
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
    }

    private fun fallbackInvitePayload(identity: IdentityMaterial): ByteArray = JSONObject()
        .put("schema", "qubee.invite.v1")
        .put("displayName", identity.displayName)
        .put("relayHandle", identity.relayHandle)
        .put("deviceId", identity.deviceId)
        .put("identityFingerprint", identity.identityFingerprint)
        .put("publicBundleBase64", identity.publicBundleBase64)
        .put("bootstrapToken", deriveBootstrapToken(identity.relayHandle, identity.deviceId, identity.identityFingerprint))
        .put("preferredBootstrap", "wifi-direct+ble")
        .put("turnHint", "relay-assisted-turn")
        .put("issuedAt", System.currentTimeMillis())
        .toString()
        .toByteArray(StandardCharsets.UTF_8)

    private fun deriveSessionKey(
        selfPublicBundleBase64: String,
        peerPublicBundleBase64: String,
        conversationId: String,
        peerHandle: String,
    ): ByteArray = MessageDigest.getInstance("SHA-256").digest(
        (selfPublicBundleBase64 + peerPublicBundleBase64 + conversationId + peerHandle)
            .toByteArray(StandardCharsets.UTF_8)
    )

    private fun keySpec(base64Key: String) = SecretKeySpec(decode(base64Key).copyOf(32), "AES")

    private fun decode(base64: String): ByteArray = Base64.decode(base64, Base64.DEFAULT)

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also(random::nextBytes)

    private fun normalizeInvitePayload(payloadText: String): ByteArray {
        val trimmed = payloadText.trim()
        return when {
            trimmed.startsWith(INVITE_PREFIX) -> {
                Base64.decode(trimmed.removePrefix(INVITE_PREFIX), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            }
            trimmed.startsWith("{") -> trimmed.toByteArray(StandardCharsets.UTF_8)
            else -> Base64.decode(trimmed, Base64.DEFAULT)
        }
    }

    override fun deriveBootstrapToken(relayHandle: String, deviceId: String, identityFingerprint: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$relayHandle|$deviceId|$identityFingerprint|local-bootstrap".toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(digest.copyOf(12), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    companion object {
        private const val INVITE_PREFIX = "qubee:invite:"
    }
}
