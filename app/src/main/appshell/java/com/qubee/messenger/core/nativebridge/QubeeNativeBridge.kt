package com.qubee.messenger.core.nativebridge

import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.model.NativeAvailability
import com.qubee.messenger.model.NativeBridgeStatus
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.UUID

data class NativeIdentity(
    val displayName: String,
    val deviceLabel: String,
    val identityFingerprint: String,
)

object QubeeNativeBridge {
    fun status(): NativeBridgeStatus {
        val loaded = QubeeManager.isLibraryLoaded()
        val initialized = QubeeManager.isInitialized()
        return when {
            initialized -> NativeBridgeStatus(NativeAvailability.Ready, "Native library loaded and initialized.")
            loaded -> NativeBridgeStatus(NativeAvailability.Ready, "Native library available but not initialized yet.")
            else -> NativeBridgeStatus(
                NativeAvailability.FallbackMock,
                "Native library not packaged yet. Running UI shell with deterministic mock identity flow."
            )
        }
    }

    fun initializeIfPossible(): NativeBridgeStatus {
        QubeeManager.initializeIfPossible()
        return status()
    }

    fun createIdentity(displayName: String): NativeIdentity {
        val payload = QubeeManager.generateIdentityBundleOrNull(
            displayName = displayName,
            deviceLabel = "Android device",
            relayHandle = displayName.lowercase().replace(" ", ".") + "@qubee.local",
            deviceId = "android-" + UUID.randomUUID().toString().substring(0, 8),
        )
        if (payload != null && payload.isNotEmpty()) {
            val json = JSONObject(payload.toString(StandardCharsets.UTF_8))
            return NativeIdentity(
                displayName = json.optString("displayName", displayName),
                deviceLabel = json.optString("deviceLabel", "Android device"),
                identityFingerprint = json.optString("identityFingerprint", "unknown"),
            )
        }

        val random = QubeeManager.mockIdentityBytes()
        val fingerprint = random.joinToString("") { "%02x".format(it) }.chunked(4).joinToString(" ")
        return NativeIdentity(
            displayName = displayName,
            deviceLabel = "Android demo shell",
            identityFingerprint = fingerprint.ifBlank { UUID.randomUUID().toString().take(14) },
        )
    }
}
