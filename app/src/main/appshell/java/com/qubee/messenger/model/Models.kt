package com.qubee.messenger.model

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

data class UserProfile(
    val displayName: String,
    val deviceLabel: String,
    val identityFingerprint: String,
    val publicBundleBase64: String,
    val relayHandle: String,
    val deviceId: String,
)

data class ConversationSummary(
    val id: String,
    val title: String,
    val subtitle: String,
    val peerHandle: String,
    val lastMessagePreview: String,
    val unreadCount: Int,
    val isVerified: Boolean,
    val updatedAt: Long,
    val trustResetRequired: Boolean = false,
    val lastKeyChangeAt: Long = 0L,
    val lastReadCursorAt: Long = 0L,
) {
    val updatedAtLabel: String
        get() = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(updatedAt))

    val keyChangedLabel: String?
        get() = lastKeyChangeAt.takeIf { it > 0L }?.let {
            SimpleDateFormat("MMM d HH:mm", Locale.getDefault()).format(Date(it))
        }
}

data class ChatMessage(
    val id: String = UUID.randomUUID().toString(),
    val conversationId: String,
    val sender: MessageSender,
    val body: String,
    val timestamp: Long = System.currentTimeMillis(),
    val deliveryState: DeliveryState = DeliveryState.Sent,
    val isEncrypted: Boolean = true,
    val originDeviceId: String? = null,
    val deliveredToDeviceCount: Int = 0,
    val readByDeviceCount: Int = 0,
    val lastReceiptAt: Long = 0L,
) {
    val formattedTime: String
        get() = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(timestamp))

    val receiptLabel: String
        get() = buildString {
            append(deliveryState.name.lowercase())
            if (deliveredToDeviceCount > 0) append(" · delivered:$deliveredToDeviceCount")
            if (readByDeviceCount > 0) append(" · read:$readByDeviceCount")
        }
}

data class InviteShareBundle(
    val payloadText: String,
    val relayHandle: String,
    val identityFingerprint: String,
    val shareLabel: String,
    val bootstrapToken: String,
    val preferredBootstrap: String = "wifi-direct+ble",
    val turnHint: String = "relay-assisted-turn",
)

data class InvitePreview(
    val displayName: String,
    val relayHandle: String,
    val deviceId: String,
    val identityFingerprint: String,
    val publicBundleBase64: String,
    val bootstrapToken: String,
    val preferredBootstrap: String = "wifi-direct+ble",
    val turnHint: String = "relay-assisted-turn",
)

data class InviteImportResult(
    val conversationId: String,
    val title: String,
    val relayHandle: String,
    val safetyCode: String,
    val statusMessage: String,
)

data class TrustDetails(
    val conversationId: String,
    val conversationTitle: String,
    val peerHandle: String,
    val localFingerprint: String,
    val peerFingerprint: String,
    val safetyCode: String?,
    val isVerified: Boolean,
    val trustResetRequired: Boolean,
    val previousPeerFingerprint: String?,
    val sessionId: String?,
    val sessionState: String,
    val sessionNativeBacked: Boolean,
    val pendingOutboundCount: Int,
    val lastHistorySyncAt: Long,
    val lastSeenMessageAt: Long,
    val lastKeyChangeAt: Long,
    val localDeviceId: String,
    val lastReadCursorAt: Long,
) {
    val lastHistorySyncLabel: String
        get() = if (lastHistorySyncAt <= 0L) "Never" else SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(lastHistorySyncAt))

    val lastSeenMessageLabel: String
        get() = if (lastSeenMessageAt <= 0L) "No messages yet" else SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(lastSeenMessageAt))

    val lastKeyChangeLabel: String
        get() = if (lastKeyChangeAt <= 0L) "No key changes recorded" else SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(lastKeyChangeAt))

    val lastReadCursorLabel: String
        get() = if (lastReadCursorAt <= 0L) "No multi-device read cursor yet" else SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(lastReadCursorAt))
}

enum class MessageSender { LocalUser, RemoteUser }

enum class DeliveryState { Sending, Sent, Delivered, Read, Failed }

enum class NativeAvailability { Ready, FallbackMock, Unavailable }

data class NativeBridgeStatus(
    val availability: NativeAvailability,
    val details: String,
)

enum class RelayConnectionState { Disconnected, Connecting, Authenticating, Connected, Error }

data class RelayStatus(
    val state: RelayConnectionState,
    val details: String,
    val relayUrl: String,
)


data class LinkedDeviceRecord(
    val id: String,
    val title: String,
    val subtitle: String,
    val trustLabel: String,
    val isCurrentDevice: Boolean,
    val isTrusted: Boolean,
)

data class ConnectivityDiagnostics(
    val localBootstrapDetails: String,
    val localBootstrapReady: Boolean,
    val webRtcDetails: String,
    val webRtcReady: Boolean,
    val openChannelCount: Int,
    val knownConversationCount: Int,
    val secureMessagingReady: Boolean,
    val securityPosture: String,
)
