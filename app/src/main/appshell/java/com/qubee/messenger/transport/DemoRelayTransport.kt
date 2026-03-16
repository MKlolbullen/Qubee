package com.qubee.messenger.transport

import com.qubee.messenger.model.RelayConnectionState
import com.qubee.messenger.model.RelayStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID

class DemoRelayTransport : RelayTransport {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutableEvents = MutableSharedFlow<RelayEvent>(extraBufferCapacity = 64)
    private val mutableStatus = MutableStateFlow(
        RelayStatus(
            state = RelayConnectionState.Disconnected,
            details = "Relay transport idle.",
            relayUrl = "demo://loopback",
        )
    )

    override val events: SharedFlow<RelayEvent> = mutableEvents.asSharedFlow()
    override val status: StateFlow<RelayStatus> = mutableStatus.asStateFlow()

    override suspend fun connect(config: RelayConfig, authenticator: RelayAuthenticator?) {
        mutableStatus.value = RelayStatus(
            state = RelayConnectionState.Connecting,
            details = "Connecting to ${config.relayUrl}",
            relayUrl = config.relayUrl,
        )
        delay(120)
        mutableStatus.value = RelayStatus(
            state = RelayConnectionState.Connected,
            details = "Connected in demo mode as ${config.localHandle}/${config.deviceId}",
            relayUrl = config.relayUrl,
        )
        mutableEvents.emit(RelayEvent.Authenticated(relaySessionId = "demo", handle = config.localHandle))
    }

    override suspend fun disconnect() {
        mutableStatus.value = RelayStatus(
            state = RelayConnectionState.Disconnected,
            details = "Demo relay disconnected.",
            relayUrl = mutableStatus.value.relayUrl,
        )
    }

    override suspend fun publish(envelope: RelayEnvelope): Boolean {
        scope.launch {
            delay(120)
            mutableEvents.emit(RelayEvent.DeliveryReceipt(envelope.messageId, System.currentTimeMillis()))
            delay(120)
            mutableEvents.emit(RelayEvent.ReceiptReceived(
                RelayReceipt(
                    receiptId = UUID.randomUUID().toString(),
                    messageId = envelope.messageId,
                    conversationId = envelope.conversationId,
                    senderHandle = envelope.senderHandle,
                    recipientHandle = envelope.recipientHandle,
                    recipientDeviceId = "demo-remote-device",
                    receiptType = "delivered",
                    recordedAt = System.currentTimeMillis(),
                )
            ))
        }
        return true
    }

    override suspend fun publishContactRequest(request: RelayContactRequest): Boolean = true

    override suspend fun publishReceipt(receipt: RelayReceipt): Boolean = true

    override suspend fun publishReadCursor(cursor: RelayReadCursor): Boolean {
        scope.launch {
            delay(80)
            mutableEvents.emit(RelayEvent.ReadCursorReceived(cursor))
        }
        return true
    }

    override suspend fun requestPeerBundle(peerHandle: String): Boolean {
        mutableEvents.emit(RelayEvent.PeerBundleReceived(peerHandle, null))
        return true
    }

    override suspend fun requestHistorySync(since: Long): Boolean {
        mutableEvents.emit(RelayEvent.HistorySyncReceived(RelayHistorySync(
            relaySessionId = "demo",
            syncedUntil = System.currentTimeMillis(),
            envelopes = emptyList(),
            contactRequests = emptyList(),
            receipts = emptyList(),
            readCursors = emptyList(),
        )))
        return true
    }

    override suspend fun sendSignaling(fromHandle: String, toHandle: String, signalType: String, payload: String): Boolean = false

    override suspend fun injectIncoming(envelope: RelayEnvelope) {
        scope.launch {
            delay(260)
            mutableEvents.emit(RelayEvent.EnvelopeReceived(envelope))
        }
    }
}
