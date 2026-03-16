package com.qubee.messenger.network.p2p

import com.qubee.messenger.transport.RelayEvent
import com.qubee.messenger.transport.RelayTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * WAN signaling transport that routes WebRTC SDP offers, answers, and ICE
 * candidates through the Qubee relay server.
 *
 * This enables two peers on different networks to establish a direct WebRTC
 * data channel by using the relay as a signaling server.  Once the data
 * channel is open, all subsequent message traffic flows peer-to-peer —
 * the relay is only used for the initial handshake and as a fallback.
 *
 * Wire format (relay → client):
 * ```json
 * {
 *   "type": "signaling",
 *   "fromHandle": "alice@qubee",
 *   "toHandle": "bob@qubee",
 *   "signalType": "webrtc_offer",
 *   "payload": "<JSON-encoded WebRtcBootstrapSignal>",
 *   "sentAt": 1710000000000
 * }
 * ```
 */
class RelaySignalingTransport(
    private val relayTransport: RelayTransport,
) : SignalingTransport {
    override val transportName: String = "relay-wan-signaling"

    private var scope: CoroutineScope? = null
    private val incomingMessages = MutableSharedFlow<SignalingMessage>(extraBufferCapacity = 64)
    private var localHandle: String = ""

    override suspend fun start(localHandle: String) {
        this.localHandle = localHandle
        val newScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope = newScope
        newScope.launch {
            relayTransport.events.collect { event ->
                if (event is RelayEvent.SignalingReceived && event.toHandle == localHandle) {
                    incomingMessages.emit(
                        SignalingMessage(
                            type = event.signalType,
                            peerHandle = localHandle,
                            payload = event.payload,
                            sentAt = event.sentAt,
                        )
                    )
                }
            }
        }
    }

    override suspend fun stop() {
        scope?.cancel()
        scope = null
    }

    override suspend fun publish(message: SignalingMessage) {
        // The payload is a JSON-encoded WebRtcBootstrapSignal which contains
        // toHandle.  Extract it so the relay can route the frame.
        val toHandle = runCatching {
            JSONObject(message.payload).optString("toHandle", "")
        }.getOrDefault("")
        if (toHandle.isBlank()) return

        relayTransport.sendSignaling(
            fromHandle = localHandle,
            toHandle = toHandle,
            signalType = message.type,
            payload = message.payload,
        )
    }

    override fun incoming(): Flow<SignalingMessage> = incomingMessages.asSharedFlow()
}
