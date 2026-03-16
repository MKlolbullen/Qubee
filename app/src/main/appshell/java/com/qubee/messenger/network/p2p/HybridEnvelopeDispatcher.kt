package com.qubee.messenger.network.p2p

import com.qubee.messenger.transport.RelayEnvelope
import com.qubee.messenger.transport.RelayReadCursor
import com.qubee.messenger.transport.RelayReceipt
import com.qubee.messenger.transport.RelayTransport
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

sealed interface HybridEnvelopeEvent {
    data class EnvelopeReceived(val envelope: RelayEnvelope) : HybridEnvelopeEvent
    data class ReceiptReceived(val receipt: RelayReceipt) : HybridEnvelopeEvent
    data class ReadCursorReceived(val cursor: RelayReadCursor) : HybridEnvelopeEvent
    data class TransportNotice(val message: String) : HybridEnvelopeEvent
}

enum class DeliveryPath {
    WebRtc,
    Relay,
    Failed,
}

class HybridEnvelopeDispatcher(
    private val webRtcTransport: WebRtcEnvelopeTransport,
    private val relayTransport: RelayTransport,
) {
    val events: Flow<HybridEnvelopeEvent> = webRtcTransport.events.map {
        when (it) {
            is WebRtcEnvelopeEvent.EnvelopeReceived -> HybridEnvelopeEvent.EnvelopeReceived(it.envelope)
            is WebRtcEnvelopeEvent.ReceiptReceived -> HybridEnvelopeEvent.ReceiptReceived(it.receipt)
            is WebRtcEnvelopeEvent.ReadCursorReceived -> HybridEnvelopeEvent.ReadCursorReceived(it.cursor)
            is WebRtcEnvelopeEvent.TransportError -> HybridEnvelopeEvent.TransportNotice(it.message)
        }
    }

    suspend fun start(localHandle: String, localDeviceId: String) {
        webRtcTransport.start(localHandle, localDeviceId)
    }

    suspend fun stop() {
        webRtcTransport.stop()
    }

    suspend fun sendEnvelope(envelope: RelayEnvelope): DeliveryPath {
        if (webRtcTransport.sendEnvelope(envelope)) return DeliveryPath.WebRtc
        return if (relayTransport.publish(envelope)) DeliveryPath.Relay else DeliveryPath.Failed
    }

    suspend fun sendReceipt(peerHandle: String, receipt: RelayReceipt): DeliveryPath {
        if (webRtcTransport.sendReceipt(peerHandle, receipt)) return DeliveryPath.WebRtc
        return if (relayTransport.publishReceipt(receipt)) DeliveryPath.Relay else DeliveryPath.Failed
    }

    suspend fun sendReadCursor(peerHandle: String, cursor: RelayReadCursor): DeliveryPath {
        if (webRtcTransport.sendReadCursor(peerHandle, cursor)) return DeliveryPath.WebRtc
        return if (relayTransport.publishReadCursor(cursor)) DeliveryPath.Relay else DeliveryPath.Failed
    }

    suspend fun bootstrapPeer(peerHandle: String, iceRestart: Boolean = false) {
        webRtcTransport.bootstrapPeer(peerHandle, iceRestart)
    }

    fun configureLocalBootstrap(localBootstrapToken: String) {
        webRtcTransport.configureLocalBootstrap(localBootstrapToken)
    }

    fun registerPeerBootstrap(hint: BootstrapPeerHint) {
        webRtcTransport.registerPeerBootstrap(hint)
    }

    fun hasOpenChannel(peerHandle: String): Boolean = webRtcTransport.hasOpenChannel(peerHandle)
}
