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
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class WebSocketRelayTransport : RelayTransport {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()
    private val mutableEvents = MutableSharedFlow<RelayEvent>(extraBufferCapacity = 128)
    private val mutableStatus = MutableStateFlow(
        RelayStatus(
            state = RelayConnectionState.Disconnected,
            details = "Relay transport idle.",
            relayUrl = "ws://10.0.2.2:8787/ws",
        )
    )
    private var webSocket: WebSocket? = null
    private var activeConfig: RelayConfig? = null
    private var activeAuthenticator: RelayAuthenticator? = null
    private val reconnectAttempts = AtomicInteger(0)

    override val events: SharedFlow<RelayEvent> = mutableEvents.asSharedFlow()
    override val status: StateFlow<RelayStatus> = mutableStatus.asStateFlow()

    override suspend fun connect(config: RelayConfig, authenticator: RelayAuthenticator?) {
        activeConfig = config
        activeAuthenticator = authenticator
        openSocket(config)
    }

    override suspend fun disconnect() {
        reconnectAttempts.set(0)
        webSocket?.close(1000, "client disconnect")
        webSocket = null
        mutableStatus.value = RelayStatus(
            state = RelayConnectionState.Disconnected,
            details = "Relay disconnected.",
            relayUrl = activeConfig?.relayUrl ?: mutableStatus.value.relayUrl,
        )
    }

    override suspend fun publish(envelope: RelayEnvelope): Boolean = sendOrError(
        RelayProtocol.publishJson(envelope),
        "WebSocket publish failed",
        "Relay publish failed; websocket not ready.",
    )

    override suspend fun publishContactRequest(request: RelayContactRequest): Boolean = sendOrError(
        RelayProtocol.contactRequestJson(request),
        "Contact request publish failed for ${request.recipientHandle}",
    )

    override suspend fun publishReceipt(receipt: RelayReceipt): Boolean = sendOrError(
        RelayProtocol.receiptJson(receipt),
        "Receipt publish failed for ${receipt.messageId}",
    )

    override suspend fun publishReadCursor(cursor: RelayReadCursor): Boolean = sendOrError(
        RelayProtocol.readCursorJson(cursor),
        "Read cursor publish failed for ${cursor.conversationId}",
    )

    override suspend fun requestPeerBundle(peerHandle: String): Boolean = sendOrError(
        RelayProtocol.requestPeerBundleJson(peerHandle),
        "Peer bundle request failed for $peerHandle",
    )

    override suspend fun requestHistorySync(since: Long): Boolean = sendOrError(
        RelayProtocol.requestHistorySyncJson(since),
        "History sync request failed from cursor $since",
    )

    override suspend fun sendSignaling(
        fromHandle: String,
        toHandle: String,
        signalType: String,
        payload: String,
    ): Boolean = sendOrError(
        RelayProtocol.signalingJson(fromHandle, toHandle, signalType, payload, System.currentTimeMillis()),
        "Signaling send failed for $toHandle",
    )

    private suspend fun sendOrError(payload: String, transportError: String, statusError: String? = null): Boolean {
        val success = webSocket?.send(payload) == true
        if (!success) {
            statusError?.let {
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Error,
                    details = it,
                    relayUrl = activeConfig?.relayUrl ?: mutableStatus.value.relayUrl,
                )
            }
            mutableEvents.emit(RelayEvent.TransportError(transportError))
        }
        return success
    }

    private fun openSocket(config: RelayConfig) {
        webSocket?.cancel()
        mutableStatus.value = RelayStatus(
            state = RelayConnectionState.Connecting,
            details = "Connecting to ${config.relayUrl}",
            relayUrl = config.relayUrl,
        )
        val request = Request.Builder().url(config.relayUrl).build()
        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                reconnectAttempts.set(0)
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Authenticating,
                    details = "WebSocket connected. Waiting for relay auth.",
                    relayUrl = config.relayUrl,
                )
                scope.launch {
                    val hello = activeAuthenticator?.createHello(config)
                    if (hello == null) {
                        mutableStatus.value = RelayStatus(
                            state = RelayConnectionState.Error,
                            details = "Relay auth unavailable: no identity/authenticator configured.",
                            relayUrl = config.relayUrl,
                        )
                        return@launch
                    }
                    webSocket.send(RelayProtocol.helloJson(hello))
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                scope.launch { handleTextFrame(text) }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                scope.launch { handleTextFrame(bytes.utf8()) }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, reason)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Disconnected,
                    details = "Relay closed: $reason",
                    relayUrl = config.relayUrl,
                )
                scheduleReconnect()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Error,
                    details = "Relay failure: ${t.message ?: "unknown error"}",
                    relayUrl = config.relayUrl,
                )
                scope.launch {
                    mutableEvents.emit(RelayEvent.TransportError(t.message ?: "Relay websocket failure"))
                }
                scheduleReconnect()
            }
        })
    }

    private suspend fun handleTextFrame(frameText: String) {
        when (val frame = RelayProtocol.parse(frameText)) {
            is ParsedRelayFrame.Challenge -> {
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Authenticating,
                    details = "Signing relay challenge.",
                    relayUrl = activeConfig?.relayUrl ?: mutableStatus.value.relayUrl,
                )
                val auth = activeAuthenticator?.signChallenge(frame.challenge, frame.relaySessionId)
                if (auth == null) {
                    mutableStatus.value = RelayStatus(
                        state = RelayConnectionState.Error,
                        details = "Relay auth failed: missing signature. Native bundle likely not restored.",
                        relayUrl = activeConfig?.relayUrl ?: mutableStatus.value.relayUrl,
                    )
                    mutableEvents.emit(RelayEvent.TransportError("Relay auth proof unavailable"))
                    return
                }
                webSocket?.send(RelayProtocol.authenticateJson(auth))
            }
            is ParsedRelayFrame.Authenticated -> {
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Connected,
                    details = "Authenticated as ${frame.handle}",
                    relayUrl = activeConfig?.relayUrl ?: mutableStatus.value.relayUrl,
                )
                mutableEvents.emit(RelayEvent.Authenticated(frame.relaySessionId, frame.handle))
            }
            is ParsedRelayFrame.Envelope -> mutableEvents.emit(RelayEvent.EnvelopeReceived(frame.envelope))
            is ParsedRelayFrame.DeliveryAck -> mutableEvents.emit(RelayEvent.DeliveryReceipt(frame.messageId, frame.deliveredAt))
            is ParsedRelayFrame.PeerBundle -> mutableEvents.emit(RelayEvent.PeerBundleReceived(frame.peerHandle, frame.publicBundleBase64))
            is ParsedRelayFrame.ContactRequest -> mutableEvents.emit(RelayEvent.ContactRequestReceived(frame.request))
            is ParsedRelayFrame.HistorySync -> mutableEvents.emit(RelayEvent.HistorySyncReceived(frame.sync))
            is ParsedRelayFrame.Receipt -> mutableEvents.emit(RelayEvent.ReceiptReceived(frame.receipt))
            is ParsedRelayFrame.ReadCursor -> mutableEvents.emit(RelayEvent.ReadCursorReceived(frame.cursor))
            is ParsedRelayFrame.Signaling -> mutableEvents.emit(RelayEvent.SignalingReceived(frame.fromHandle, frame.toHandle, frame.signalType, frame.payload, frame.sentAt))
            is ParsedRelayFrame.Error -> {
                mutableStatus.value = RelayStatus(
                    state = RelayConnectionState.Error,
                    details = frame.message,
                    relayUrl = activeConfig?.relayUrl ?: mutableStatus.value.relayUrl,
                )
                mutableEvents.emit(RelayEvent.TransportError(frame.message))
            }
            ParsedRelayFrame.Ignored -> Unit
        }
    }

    private fun scheduleReconnect() {
        val config = activeConfig ?: return
        val attempt = reconnectAttempts.incrementAndGet().coerceAtMost(6)
        val delayMs = 1_000L * attempt
        mutableStatus.value = RelayStatus(
            state = RelayConnectionState.Connecting,
            details = "Relay reconnect in ${delayMs / 1000}s (attempt $attempt)",
            relayUrl = config.relayUrl,
        )
        scope.launch {
            delay(delayMs)
            openSocket(config)
        }
    }
}
