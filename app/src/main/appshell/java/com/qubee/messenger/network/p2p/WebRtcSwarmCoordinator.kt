package com.qubee.messenger.network.p2p

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class WebRtcSwarmCoordinator(
    private val localBootstrapTransport: SignalingTransport,
    private val wanBootstrapTransport: SignalingTransport,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val incomingMessages = MutableSharedFlow<SignalingMessage>(extraBufferCapacity = 64)
    private val peerHints = ConcurrentHashMap<String, BootstrapPeerHint>()
    private var localBootstrapToken: String = ""

    suspend fun start(localHandle: String) {
        localBootstrapTransport.start(localHandle)
        wanBootstrapTransport.start(localHandle)
        scope.launch { localBootstrapTransport.incoming().collect { incomingMessages.emit(it) } }
        scope.launch { wanBootstrapTransport.incoming().collect { incomingMessages.emit(it) } }
    }

    suspend fun stop() {
        localBootstrapTransport.stop()
        wanBootstrapTransport.stop()
    }

    fun incoming(): Flow<SignalingMessage> = incomingMessages.asSharedFlow()

    fun updateLocalBootstrapIdentity(localBootstrapToken: String, localDeviceId: String) {
        this.localBootstrapToken = localBootstrapToken
        listOf(localBootstrapTransport, wanBootstrapTransport).forEach {
            (it as? BootstrapRegistrationSink)?.updateLocalBootstrapIdentity(localBootstrapToken, localDeviceId)
        }
    }

    fun registerPeerBootstrap(hint: BootstrapPeerHint) {
        peerHints[hint.peerHandle] = hint
        listOf(localBootstrapTransport, wanBootstrapTransport).forEach {
            (it as? BootstrapRegistrationSink)?.registerPeerBootstrap(hint)
        }
    }

    suspend fun announceOffer(peerHandle: String, fromHandle: String, fromDeviceId: String, sdp: String, turnPolicy: TurnPolicy? = null) {
        val hint = peerHints[peerHandle]
        publishBootstrapSignal(
            WebRtcBootstrapSignal.Offer(
                fromHandle = fromHandle,
                fromDeviceId = fromDeviceId,
                toHandle = peerHandle,
                sentAt = System.currentTimeMillis(),
                sdp = sdp,
                bootstrapToken = hint?.peerBootstrapToken ?: localBootstrapToken,
                preferredBootstrap = hint?.preference?.name,
                turnPolicy = turnPolicy,
            )
        )
    }

    suspend fun announceAnswer(peerHandle: String, fromHandle: String, fromDeviceId: String, sdp: String, turnPolicy: TurnPolicy? = null) {
        val hint = peerHints[peerHandle]
        publishBootstrapSignal(
            WebRtcBootstrapSignal.Answer(
                fromHandle = fromHandle,
                fromDeviceId = fromDeviceId,
                toHandle = peerHandle,
                sentAt = System.currentTimeMillis(),
                sdp = sdp,
                bootstrapToken = hint?.peerBootstrapToken ?: localBootstrapToken,
                preferredBootstrap = hint?.preference?.name,
                turnPolicy = turnPolicy,
            )
        )
    }

    suspend fun announceIceCandidate(peerHandle: String, fromHandle: String, fromDeviceId: String, sdpMid: String?, sdpMLineIndex: Int, candidate: String) {
        val hint = peerHints[peerHandle]
        publishBootstrapSignal(
            WebRtcBootstrapSignal.IceCandidateSignal(
                fromHandle = fromHandle,
                fromDeviceId = fromDeviceId,
                toHandle = peerHandle,
                sentAt = System.currentTimeMillis(),
                sdpMid = sdpMid,
                sdpMLineIndex = sdpMLineIndex,
                candidate = candidate,
                bootstrapToken = hint?.peerBootstrapToken ?: localBootstrapToken,
            )
        )
    }

    private suspend fun publishBootstrapSignal(signal: WebRtcBootstrapSignal) {
        val message = WebRtcBootstrapCodec.encode(signal)
        localBootstrapTransport.publish(message)
        wanBootstrapTransport.publish(message)
    }
}
