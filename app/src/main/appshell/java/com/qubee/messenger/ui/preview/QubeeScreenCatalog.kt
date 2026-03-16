package com.qubee.messenger.ui.preview

import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import com.qubee.messenger.model.ChatMessage
import com.qubee.messenger.model.ConnectivityDiagnostics
import com.qubee.messenger.model.ConversationSummary
import com.qubee.messenger.model.DeliveryState
import com.qubee.messenger.model.InviteShareBundle
import com.qubee.messenger.model.LinkedDeviceRecord
import com.qubee.messenger.model.MessageSender
import com.qubee.messenger.model.NativeAvailability
import com.qubee.messenger.model.NativeBridgeStatus
import com.qubee.messenger.model.RelayConnectionState
import com.qubee.messenger.model.RelayStatus
import com.qubee.messenger.model.TrustDetails
import com.qubee.messenger.model.UserProfile
import com.qubee.messenger.model.VaultLockState
import com.qubee.messenger.model.VaultStatus
import com.qubee.messenger.ui.screens.ChatScreen
import com.qubee.messenger.ui.screens.ConnectivityScreen
import com.qubee.messenger.ui.screens.ConversationsScreen
import com.qubee.messenger.ui.screens.DangerZoneScreen
import com.qubee.messenger.ui.screens.InviteScreen
import com.qubee.messenger.ui.screens.LinkedDevicesScreen
import com.qubee.messenger.ui.screens.OnboardingScreen
import com.qubee.messenger.ui.screens.SettingsScreen
import com.qubee.messenger.ui.screens.TrustDetailsScreen
import com.qubee.messenger.ui.screens.UnlockScreen
import com.qubee.messenger.ui.theme.QubeeTheme

private object PreviewSeed {
    private val now = 1_725_000_000_000L

    val profile = UserProfile(
        displayName = "Victor",
        deviceLabel = "Pixel 8 Pro · Primary",
        identityFingerprint = "7A91-4C8E-22D0-9F11",
        publicBundleBase64 = "BASE64-PUBLIC-BUNDLE",
        relayHandle = "@victor:relay.qubee.test",
        deviceId = "device-primary-a1",
    )

    val nativeReady = NativeBridgeStatus(
        availability = NativeAvailability.Ready,
        details = "JNI bridge loaded, native hybrid bootstrap available, and vault-backed state restored.",
    )

    val relayConnected = RelayStatus(
        state = RelayConnectionState.Connected,
        details = "Relay websocket authenticated. Recovery sync and receipt reconciliation are alive.",
        relayUrl = "wss://relay.qubee.test/ws",
    )

    val invite = InviteShareBundle(
        payloadText = "qubee://invite?handle=%40victor&bundle=BASE64&token=PAIR-7788",
        relayHandle = profile.relayHandle,
        identityFingerprint = profile.identityFingerprint,
        shareLabel = "Victor on Qubee",
        bootstrapToken = "PAIR-7788",
    )

    val conversations = listOf(
        ConversationSummary(
            id = "conv-1",
            title = "Alice",
            subtitle = "@alice:relay.qubee.test",
            peerHandle = "@alice:relay.qubee.test",
            lastMessagePreview = "Session rehydrated on my laptop too.",
            unreadCount = 2,
            isVerified = true,
            updatedAt = now,
            lastReadCursorAt = now - 60_000,
        ),
        ConversationSummary(
            id = "conv-2",
            title = "Bob",
            subtitle = "@bob:relay.qubee.test",
            peerHandle = "@bob:relay.qubee.test",
            lastMessagePreview = "We should rotate after the key-change event.",
            unreadCount = 0,
            isVerified = false,
            updatedAt = now - 3_600_000,
            trustResetRequired = true,
            lastKeyChangeAt = now - 7_200_000,
        ),
    )

    val messages = listOf(
        ChatMessage(
            conversationId = "conv-1",
            sender = MessageSender.RemoteUser,
            body = "I scanned your invite QR. Session came up clean.",
            timestamp = now - 180_000,
        ),
        ChatMessage(
            conversationId = "conv-1",
            sender = MessageSender.LocalUser,
            body = "Nice. Read cursors should now sync across sibling devices.",
            timestamp = now - 120_000,
            deliveryState = DeliveryState.Read,
            deliveredToDeviceCount = 2,
            readByDeviceCount = 1,
        ),
        ChatMessage(
            conversationId = "conv-1",
            sender = MessageSender.RemoteUser,
            body = "Confirmed. The trust screen finally looks like it means business.",
            timestamp = now - 60_000,
        ),
    )

    val trust = TrustDetails(
        conversationId = "conv-1",
        conversationTitle = "Alice",
        peerHandle = "@alice:relay.qubee.test",
        localFingerprint = profile.identityFingerprint,
        peerFingerprint = "2B60-D91F-73E4-5512",
        safetyCode = "2184 7732 9910",
        isVerified = true,
        trustResetRequired = false,
        previousPeerFingerprint = "2B60-D91F-73E4-4410",
        sessionId = "sess-001",
        sessionState = "active",
        sessionNativeBacked = true,
        pendingOutboundCount = 0,
        lastHistorySyncAt = now - 20_000,
        lastSeenMessageAt = now - 60_000,
        lastKeyChangeAt = now - 1_800_000,
        localDeviceId = profile.deviceId,
        lastReadCursorAt = now - 15_000,
    )

    val linkedDevices = listOf(
        LinkedDeviceRecord(
            id = "device-primary-a1",
            title = "Pixel 8 Pro",
            subtitle = "Current device · last active just now",
            trustLabel = "Primary",
            isCurrentDevice = true,
            isTrusted = true,
        ),
        LinkedDeviceRecord(
            id = "device-laptop-b2",
            title = "ThinkPad X1",
            subtitle = "Pending enrollment record via relay-assisted sync",
            trustLabel = "Pending",
            isCurrentDevice = false,
            isTrusted = false,
        ),
    )

    val diagnostics = ConnectivityDiagnostics(
        localBootstrapDetails = "BLE and Wi-Fi Direct bootstrap paths are provisioned.",
        localBootstrapReady = true,
        webRtcDetails = "Two RTC channels are open and receipt sync is current.",
        webRtcReady = true,
        openChannelCount = 2,
        knownConversationCount = conversations.size,
        secureMessagingReady = true,
        securityPosture = "Native hybrid bootstrap is available and the preview shell path is not currently active.",
    )

    val vault = VaultStatus(
        state = VaultLockState.Locked,
        details = "Secure vault locked. Authenticate to reopen SQLCipher and restore the local identity.",
        hasExistingVault = true,
    )
}

@Composable
private fun PreviewFrame(content: @Composable () -> Unit) {
    QubeeTheme {
        Surface {
            content()
        }
    }
}

@Preview(name = "Unlock", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun UnlockPreview() = PreviewFrame {
    UnlockScreen(
        vaultStatus = PreviewSeed.vault,
        nativeStatus = PreviewSeed.nativeReady,
        relayStatus = PreviewSeed.relayConnected,
        onUnlock = {},
    )
}

@Preview(name = "Onboarding", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun OnboardingPreview() = PreviewFrame {
    OnboardingScreen(
        nativeStatus = PreviewSeed.nativeReady,
        relayStatus = PreviewSeed.relayConnected,
        onCreateIdentity = {},
    )
}

@Preview(name = "Conversations", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun ConversationsPreview() = PreviewFrame {
    ConversationsScreen(
        profile = PreviewSeed.profile,
        nativeStatus = PreviewSeed.nativeReady,
        relayStatus = PreviewSeed.relayConnected,
        conversations = PreviewSeed.conversations,
        onConversationClick = {},
    )
}

@Preview(name = "Invite", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun InvitePreview() = PreviewFrame {
    InviteScreen(
        inviteShare = PreviewSeed.invite,
        notice = "Invite imported and safety code generated.",
        onImportInvite = {},
        onInviteShared = {},
        onDismissNotice = {},
    )
}

@Preview(name = "Chat", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun ChatPreview() = PreviewFrame {
    ChatScreen(
        conversation = PreviewSeed.conversations.first(),
        messages = PreviewSeed.messages,
        relayStatus = PreviewSeed.relayConnected,
        safetyCode = PreviewSeed.trust.safetyCode,
        onVerifyContact = {},
        onOpenTrustDetails = {},
        onSend = {},
    )
}

@Preview(name = "Trust", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun TrustPreview() = PreviewFrame {
    TrustDetailsScreen(
        trustDetails = PreviewSeed.trust,
        onVerifyContact = {},
        onResetTrust = {},
    )
}

@Preview(name = "Settings", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun SettingsPreview() = PreviewFrame {
    SettingsScreen(
        profile = PreviewSeed.profile,
        inviteShare = PreviewSeed.invite,
        nativeStatus = PreviewSeed.nativeReady,
        relayStatus = PreviewSeed.relayConnected,
        onOpenLinkedDevices = {},
        onOpenConnectivity = {},
        onOpenDangerZone = {},
    )
}

@Preview(name = "Linked devices", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun LinkedDevicesPreview() = PreviewFrame {
    LinkedDevicesScreen(
        profile = PreviewSeed.profile,
        linkedDevices = PreviewSeed.linkedDevices,
    )
}

@Preview(name = "Connectivity", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun ConnectivityPreview() = PreviewFrame {
    ConnectivityScreen(
        nativeStatus = PreviewSeed.nativeReady,
        relayStatus = PreviewSeed.relayConnected,
        diagnostics = PreviewSeed.diagnostics,
    )
}

@Preview(name = "Danger zone", showBackground = true, backgroundColor = 0xFF081012)
@Composable
private fun DangerZonePreview() = PreviewFrame {
    DangerZoneScreen(onConfirmNuke = {})
}
