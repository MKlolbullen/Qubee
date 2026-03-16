package com.qubee.messenger.transport

import com.qubee.messenger.model.RelayStatus
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

data class RelayConfig(
    val relayUrl: String,
    val localHandle: String,
    val deviceId: String,
    val displayName: String,
)

data class RelayEnvelope(
    val messageId: String,
    val conversationId: String,
    val senderHandle: String,
    val recipientHandle: String,
    val sessionId: String,
    val ciphertextBase64: String,
    val algorithm: String,
    val sentAt: Long,
    val senderDeviceId: String = "",
)

data class RelayHello(
    val handle: String,
    val deviceId: String,
    val displayName: String,
    val publicBundleBase64: String,
    val identityFingerprint: String,
)

data class RelayAuthProof(
    val handle: String,
    val relaySessionId: String,
    val challenge: String,
    val publicBundleBase64: String,
    val identityFingerprint: String,
    val signatureBase64: String,
)

data class RelayContactRequest(
    val requestId: String,
    val senderHandle: String,
    val recipientHandle: String,
    val senderDisplayName: String,
    val publicBundleBase64: String,
    val identityFingerprint: String,
    val sentAt: Long,
)

data class RelayReceipt(
    val receiptId: String,
    val messageId: String,
    val conversationId: String,
    val senderHandle: String,
    val recipientHandle: String,
    val recipientDeviceId: String,
    val receiptType: String,
    val recordedAt: Long,
)

data class RelayReadCursor(
    val cursorId: String,
    val conversationId: String,
    val handle: String,
    val deviceId: String,
    val readThroughTimestamp: Long,
    val recordedAt: Long,
)

data class RelayHistorySync(
    val relaySessionId: String,
    val syncedUntil: Long,
    val envelopes: List<RelayEnvelope>,
    val contactRequests: List<RelayContactRequest>,
    val receipts: List<RelayReceipt>,
    val readCursors: List<RelayReadCursor>,
)

interface RelayAuthenticator {
    suspend fun createHello(config: RelayConfig): RelayHello
    suspend fun signChallenge(challenge: String, relaySessionId: String): RelayAuthProof?
}

sealed interface RelayEvent {
    data class EnvelopeReceived(val envelope: RelayEnvelope) : RelayEvent
    data class DeliveryReceipt(val messageId: String, val deliveredAt: Long) : RelayEvent
    data class Authenticated(val relaySessionId: String, val handle: String) : RelayEvent
    data class PeerBundleReceived(val peerHandle: String, val publicBundleBase64: String?) : RelayEvent
    data class ContactRequestReceived(val request: RelayContactRequest) : RelayEvent
    data class HistorySyncReceived(val sync: RelayHistorySync) : RelayEvent
    data class ReceiptReceived(val receipt: RelayReceipt) : RelayEvent
    data class ReadCursorReceived(val cursor: RelayReadCursor) : RelayEvent
    data class SignalingReceived(val fromHandle: String, val toHandle: String, val signalType: String, val payload: String, val sentAt: Long) : RelayEvent
    data class TransportError(val message: String) : RelayEvent
}

interface RelayTransport {
    val events: SharedFlow<RelayEvent>
    val status: StateFlow<RelayStatus>

    suspend fun connect(config: RelayConfig, authenticator: RelayAuthenticator? = null)
    suspend fun disconnect()
    suspend fun publish(envelope: RelayEnvelope): Boolean
    suspend fun publishContactRequest(request: RelayContactRequest): Boolean
    suspend fun publishReceipt(receipt: RelayReceipt): Boolean
    suspend fun publishReadCursor(cursor: RelayReadCursor): Boolean
    suspend fun requestPeerBundle(peerHandle: String): Boolean
    suspend fun requestHistorySync(since: Long): Boolean
    suspend fun sendSignaling(fromHandle: String, toHandle: String, signalType: String, payload: String): Boolean
    suspend fun injectIncoming(envelope: RelayEnvelope) {}
}
