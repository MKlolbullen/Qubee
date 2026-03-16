package com.qubee.messenger.network.p2p

import android.content.Context
import com.qubee.messenger.transport.RelayEnvelope
import com.qubee.messenger.transport.RelayReadCursor
import com.qubee.messenger.transport.RelayReceipt
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import java.lang.reflect.Proxy
import java.nio.ByteBuffer
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

sealed interface WebRtcEnvelopeEvent {
    data class EnvelopeReceived(val envelope: RelayEnvelope) : WebRtcEnvelopeEvent
    data class ReceiptReceived(val receipt: RelayReceipt) : WebRtcEnvelopeEvent
    data class ReadCursorReceived(val cursor: RelayReadCursor) : WebRtcEnvelopeEvent
    data class TransportError(val message: String) : WebRtcEnvelopeEvent
}

enum class WebRtcPathState { Idle, Bootstrapping, Ready, Degraded }

data class WebRtcPathStatus(
    val state: WebRtcPathState = WebRtcPathState.Idle,
    val details: String = "WebRTC data path idle.",
    val openChannelCount: Int = 0,
)

private data class PeerRtcSession(
    val peerHandle: String,
    val peerConnection: PeerConnection,
    var dataChannel: DataChannel? = null,
    var remoteDeviceId: String = "",
    var initiatedLocally: Boolean = false,
)

private sealed interface RtcFrame {
    data class EnvelopeFrame(val envelope: RelayEnvelope) : RtcFrame
    data class ReceiptFrame(val receipt: RelayReceipt) : RtcFrame
    data class ReadCursorFrame(val cursor: RelayReadCursor) : RtcFrame
}

class WebRtcEnvelopeTransport(
    private val appContext: Context,
    private val coordinator: WebRtcSwarmCoordinator,
    private val defaultTurnPolicy: TurnPolicy = TurnPolicy(),
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutableEvents = MutableSharedFlow<WebRtcEnvelopeEvent>(extraBufferCapacity = 64)
    private val mutableStatus = MutableStateFlow(WebRtcPathStatus())
    private val sessions = LinkedHashMap<String, PeerRtcSession>()
    private val seenBootstrapSignals = LinkedHashSet<String>()
    private val peerTurnPolicies = LinkedHashMap<String, TurnPolicy>()
    private val rehydrationManager = ChannelRehydrationManager { peerHandle, iceRestart -> bootstrapPeer(peerHandle, iceRestart) }
    private var localHandle: String = ""
    private var localDeviceId: String = ""
    private var localBootstrapToken: String = ""
    private var initialized = false
    private lateinit var peerConnectionFactory: PeerConnectionFactory

    val events: SharedFlow<WebRtcEnvelopeEvent> = mutableEvents.asSharedFlow()
    val status: StateFlow<WebRtcPathStatus> = mutableStatus.asStateFlow()

    private fun openChannelCount(): Int = sessions.values.count { it.dataChannel?.state() == DataChannel.State.OPEN }

    private fun pushStatus(state: WebRtcPathState, details: String) {
        mutableStatus.value = WebRtcPathStatus(state = state, details = details, openChannelCount = openChannelCount())
    }

    suspend fun start(localHandle: String, localDeviceId: String) {
        this.localHandle = localHandle
        this.localDeviceId = localDeviceId
        coordinator.updateLocalBootstrapIdentity(localBootstrapToken, localDeviceId)
        if (!initialized) {
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(appContext)
                    .setFieldTrials("WebRTC-DataChannel-Only/Enabled/")
                    .createInitializationOptions(),
            )
            peerConnectionFactory = PeerConnectionFactory.builder().createPeerConnectionFactory()
            initialized = true
        }
        coordinator.start(localHandle)
        pushStatus(WebRtcPathState.Bootstrapping, "Listening for bootstrap signaling.")
        scope.launch {
            coordinator.incoming().collect { message ->
                if (message.peerHandle == this@WebRtcEnvelopeTransport.localHandle) {
                    handleBootstrapSignal(message)
                }
            }
        }
    }

    suspend fun stop() {
        sessions.values.forEach { session ->
            session.dataChannel?.close()
            session.peerConnection.close()
        }
        sessions.clear()
        coordinator.stop()
        pushStatus(WebRtcPathState.Idle, "WebRTC data path stopped.")
    }

    fun configureLocalBootstrap(localBootstrapToken: String) {
        this.localBootstrapToken = localBootstrapToken
        coordinator.updateLocalBootstrapIdentity(localBootstrapToken, localDeviceId)
    }

    fun registerPeerBootstrap(hint: BootstrapPeerHint) {
        coordinator.registerPeerBootstrap(hint)
    }

    suspend fun bootstrapPeer(peerHandle: String, iceRestart: Boolean = false) {
        val session = ensurePeerSession(peerHandle, initiator = true)
        if (session.dataChannel == null) {
            session.dataChannel = createLocalDataChannel(peerHandle, session.peerConnection)
        }
        val offer = session.peerConnection.createOfferAwait(createOfferConstraints(iceRestart))
        session.peerConnection.setLocalDescriptionAwait(offer)
        coordinator.announceOffer(
            peerHandle = peerHandle,
            fromHandle = localHandle,
            fromDeviceId = localDeviceId,
            sdp = offer.description,
            turnPolicy = peerTurnPolicies[peerHandle] ?: defaultTurnPolicy,
        )
        pushStatus(
            WebRtcPathState.Bootstrapping,
            if (iceRestart) "Rehydrating channel for $peerHandle with ICE restart." else "Sent SDP offer for $peerHandle.",
        )
    }

    suspend fun sendEnvelope(envelope: RelayEnvelope): Boolean {
        val sent = sendFrame(
            peerHandle = envelope.recipientHandle,
            frame = RtcFrame.EnvelopeFrame(envelope),
            unavailableNotice = "No open data channel for ${envelope.recipientHandle}; relay fallback still required.",
        )
        if (sent) pushStatus(WebRtcPathState.Ready, "Envelope delivered over WebRTC data channel.")
        return sent
    }

    suspend fun sendReceipt(peerHandle: String, receipt: RelayReceipt): Boolean = sendFrame(
        peerHandle = peerHandle,
        frame = RtcFrame.ReceiptFrame(receipt),
        unavailableNotice = "No open WebRTC path for $peerHandle; receipt falls back to relay.",
    )

    suspend fun sendReadCursor(peerHandle: String, cursor: RelayReadCursor): Boolean = sendFrame(
        peerHandle = peerHandle,
        frame = RtcFrame.ReadCursorFrame(cursor),
        unavailableNotice = "No open WebRTC path for $peerHandle; read cursor falls back to relay.",
    )

    fun hasOpenChannel(peerHandle: String): Boolean = sessions[peerHandle]?.dataChannel?.state() == DataChannel.State.OPEN

    private suspend fun sendFrame(peerHandle: String, frame: RtcFrame, unavailableNotice: String): Boolean {
        val channel = sessions[peerHandle]?.dataChannel
        if (channel?.state() != DataChannel.State.OPEN) {
            bootstrapPeer(peerHandle)
            mutableStatus.value = WebRtcPathStatus(WebRtcPathState.Degraded, unavailableNotice)
            return false
        }
        val payload = encodeFrame(frame).toByteArray(Charsets.UTF_8)
        val ok = channel.send(DataChannel.Buffer(ByteBuffer.wrap(payload), false))
        if (!ok) mutableStatus.value = WebRtcPathStatus(WebRtcPathState.Degraded, "Data channel send failed for $peerHandle.")
        return ok
    }

    private suspend fun handleBootstrapSignal(message: SignalingMessage) {
        val signal = runCatching { WebRtcBootstrapCodec.decode(message) }.getOrNull() ?: return
        if (signal.toHandle != localHandle || signal.fromHandle == localHandle) return
        val token = when (signal) {
            is WebRtcBootstrapSignal.Offer -> signal.bootstrapToken
            is WebRtcBootstrapSignal.Answer -> signal.bootstrapToken
            is WebRtcBootstrapSignal.IceCandidateSignal -> signal.bootstrapToken
        }
        if (localBootstrapToken.isNotBlank() && !token.isNullOrBlank() && token != localBootstrapToken) return
        val signalKey = listOf(message.type, signal.fromHandle, signal.fromDeviceId, signal.toHandle, signal.sentAt, message.payload).joinToString("|")
        if (!seenBootstrapSignals.add(signalKey)) return
        if (seenBootstrapSignals.size > 512) {
            repeat(128) { seenBootstrapSignals.firstOrNull()?.also(seenBootstrapSignals::remove) }
        }
        when (signal) {
            is WebRtcBootstrapSignal.Offer -> handleOffer(signal)
            is WebRtcBootstrapSignal.Answer -> handleAnswer(signal)
            is WebRtcBootstrapSignal.IceCandidateSignal -> handleIceCandidate(signal)
        }
    }

    private suspend fun handleOffer(signal: WebRtcBootstrapSignal.Offer) {
        signal.turnPolicy?.let { peerTurnPolicies[signal.fromHandle] = it }
        val session = ensurePeerSession(signal.fromHandle, initiator = false)
        session.remoteDeviceId = signal.fromDeviceId
        session.peerConnection.setRemoteDescriptionAwait(SessionDescription(SessionDescription.Type.OFFER, signal.sdp))
        val answer = session.peerConnection.createAnswerAwait(createOfferConstraints(false))
        session.peerConnection.setLocalDescriptionAwait(answer)
        coordinator.announceAnswer(
            peerHandle = signal.fromHandle,
            fromHandle = localHandle,
            fromDeviceId = localDeviceId,
            sdp = answer.description,
            turnPolicy = peerTurnPolicies[signal.fromHandle] ?: defaultTurnPolicy,
        )
        mutableStatus.value = WebRtcPathStatus(WebRtcPathState.Bootstrapping, "Accepted offer from ${signal.fromHandle}.")
    }

    private suspend fun handleAnswer(signal: WebRtcBootstrapSignal.Answer) {
        signal.turnPolicy?.let { peerTurnPolicies[signal.fromHandle] = it }
        val session = ensurePeerSession(signal.fromHandle, initiator = true)
        session.remoteDeviceId = signal.fromDeviceId
        session.peerConnection.setRemoteDescriptionAwait(SessionDescription(SessionDescription.Type.ANSWER, signal.sdp))
        mutableStatus.value = WebRtcPathStatus(WebRtcPathState.Bootstrapping, "Accepted answer from ${signal.fromHandle}.")
    }

    private suspend fun handleIceCandidate(signal: WebRtcBootstrapSignal.IceCandidateSignal) {
        val session = ensurePeerSession(signal.fromHandle, initiator = false)
        session.remoteDeviceId = signal.fromDeviceId
        session.peerConnection.addIceCandidate(IceCandidate(signal.sdpMid, signal.sdpMLineIndex, signal.candidate))
    }

    private fun ensurePeerSession(peerHandle: String, initiator: Boolean): PeerRtcSession {
        return sessions[peerHandle] ?: createPeerSession(peerHandle, initiator).also { sessions[peerHandle] = it }
    }

    private fun createPeerSession(peerHandle: String, initiator: Boolean): PeerRtcSession {
        val sessionHolder = arrayOfNulls<PeerRtcSession>(1)
        val turnPolicy = peerTurnPolicies[peerHandle] ?: defaultTurnPolicy
        val rtcConfiguration = PeerConnection.RTCConfiguration(turnPolicy.servers.map { server ->
            val builder = PeerConnection.IceServer.builder(server.urls)
            if (server.username.isNotBlank()) builder.setUsername(server.username)
            if (server.credential.isNotBlank()) builder.setPassword(server.credential)
            builder.createIceServer()
        })
        val peerConnection = peerConnectionFactory.createPeerConnection(
            rtcConfiguration,
            createPeerConnectionObserver(peerHandle, sessionHolder),
        ) ?: error("Unable to create PeerConnection for $peerHandle")

        val session = PeerRtcSession(peerHandle = peerHandle, peerConnection = peerConnection, initiatedLocally = initiator)
        sessionHolder[0] = session
        if (initiator) session.dataChannel = createLocalDataChannel(peerHandle, peerConnection)
        return session
    }

    private fun createPeerConnectionObserver(peerHandle: String, sessionHolder: Array<PeerRtcSession?>): PeerConnection.Observer {
        return Proxy.newProxyInstance(
            PeerConnection.Observer::class.java.classLoader,
            arrayOf(PeerConnection.Observer::class.java),
        ) { _, method, args ->
            when (method.name) {
                "onIceConnectionChange", "onConnectionChange", "onStandardizedIceConnectionChange" -> {
                    val stateName = args?.firstOrNull()?.toString() ?: "unknown"
                    val mapped = when {
                        stateName.contains("CONNECTED") || stateName.contains("COMPLETED") -> WebRtcPathState.Ready
                        stateName.contains("FAILED") || stateName.contains("DISCONNECTED") || stateName.contains("CLOSED") -> WebRtcPathState.Degraded
                        else -> WebRtcPathState.Bootstrapping
                    }
                    pushStatus(mapped, "Peer link state for $peerHandle is $stateName.")
                    if (mapped == WebRtcPathState.Ready) rehydrationManager.reportHealthy(peerHandle)
                    if (mapped == WebRtcPathState.Degraded) rehydrationManager.schedule(peerHandle)
                }
                "onIceCandidate" -> {
                    val candidate = args?.firstOrNull() as? IceCandidate
                    if (candidate != null) {
                        scope.launch {
                            coordinator.announceIceCandidate(
                                peerHandle = peerHandle,
                                fromHandle = localHandle,
                                fromDeviceId = localDeviceId,
                                sdpMid = candidate.sdpMid,
                                sdpMLineIndex = candidate.sdpMLineIndex,
                                candidate = candidate.sdp,
                            )
                        }
                    }
                }
                "onDataChannel" -> {
                    val dataChannel = args?.firstOrNull() as? DataChannel
                    val session = sessionHolder[0]
                    if (dataChannel != null && session != null) {
                        session.dataChannel = dataChannel
                        registerDataChannel(peerHandle, dataChannel)
                    }
                }
            }
            null
        } as PeerConnection.Observer
    }

    private fun createLocalDataChannel(peerHandle: String, peerConnection: PeerConnection): DataChannel {
        val init = DataChannel.Init().apply {
            ordered = true
            maxRetransmits = -1
        }
        val channel = peerConnection.createDataChannel("qubee", init)
        registerDataChannel(peerHandle, channel)
        return channel
    }

    private fun registerDataChannel(peerHandle: String, channel: DataChannel) {
        channel.registerObserver(object : DataChannel.Observer {
            override fun onBufferedAmountChange(previousAmount: Long) = Unit

            override fun onStateChange() {
                val state = if (channel.state() == DataChannel.State.OPEN) WebRtcPathState.Ready else WebRtcPathState.Bootstrapping
                pushStatus(state, "Data channel for $peerHandle is ${channel.state().name.lowercase()}.")
                if (state == WebRtcPathState.Ready) rehydrationManager.reportHealthy(peerHandle)
            }

            override fun onMessage(buffer: DataChannel.Buffer) {
                val bytes = ByteArray(buffer.data.remaining())
                buffer.data.get(bytes)
                scope.launch {
                    runCatching { decodeFrame(bytes.toString(Charsets.UTF_8)) }
                        .onSuccess { emitFrame(it) }
                        .onFailure { mutableEvents.emit(WebRtcEnvelopeEvent.TransportError(it.message ?: "Malformed data channel frame")) }
                }
            }
        })
    }

    private suspend fun emitFrame(frame: RtcFrame) {
        when (frame) {
            is RtcFrame.EnvelopeFrame -> mutableEvents.emit(WebRtcEnvelopeEvent.EnvelopeReceived(frame.envelope))
            is RtcFrame.ReceiptFrame -> mutableEvents.emit(WebRtcEnvelopeEvent.ReceiptReceived(frame.receipt))
            is RtcFrame.ReadCursorFrame -> mutableEvents.emit(WebRtcEnvelopeEvent.ReadCursorReceived(frame.cursor))
        }
    }

    private fun encodeFrame(frame: RtcFrame): String = when (frame) {
        is RtcFrame.EnvelopeFrame -> JSONObject().put("type", "envelope").put("payload", JSONObject()
            .put("messageId", frame.envelope.messageId)
            .put("conversationId", frame.envelope.conversationId)
            .put("senderHandle", frame.envelope.senderHandle)
            .put("recipientHandle", frame.envelope.recipientHandle)
            .put("sessionId", frame.envelope.sessionId)
            .put("ciphertextBase64", frame.envelope.ciphertextBase64)
            .put("algorithm", frame.envelope.algorithm)
            .put("sentAt", frame.envelope.sentAt)
            .put("senderDeviceId", frame.envelope.senderDeviceId)).toString()
        is RtcFrame.ReceiptFrame -> JSONObject().put("type", "receipt").put("payload", JSONObject()
            .put("receiptId", frame.receipt.receiptId)
            .put("messageId", frame.receipt.messageId)
            .put("conversationId", frame.receipt.conversationId)
            .put("senderHandle", frame.receipt.senderHandle)
            .put("recipientHandle", frame.receipt.recipientHandle)
            .put("recipientDeviceId", frame.receipt.recipientDeviceId)
            .put("receiptType", frame.receipt.receiptType)
            .put("recordedAt", frame.receipt.recordedAt)).toString()
        is RtcFrame.ReadCursorFrame -> JSONObject().put("type", "read_cursor").put("payload", JSONObject()
            .put("cursorId", frame.cursor.cursorId)
            .put("conversationId", frame.cursor.conversationId)
            .put("handle", frame.cursor.handle)
            .put("deviceId", frame.cursor.deviceId)
            .put("readThroughTimestamp", frame.cursor.readThroughTimestamp)
            .put("recordedAt", frame.cursor.recordedAt)).toString()
    }

    private fun decodeFrame(raw: String): RtcFrame {
        val frame = JSONObject(raw)
        val payload = frame.getJSONObject("payload")
        return when (frame.getString("type")) {
            "envelope" -> RtcFrame.EnvelopeFrame(
                RelayEnvelope(
                    messageId = payload.getString("messageId"),
                    conversationId = payload.getString("conversationId"),
                    senderHandle = payload.getString("senderHandle"),
                    recipientHandle = payload.getString("recipientHandle"),
                    sessionId = payload.getString("sessionId"),
                    ciphertextBase64 = payload.getString("ciphertextBase64"),
                    algorithm = payload.getString("algorithm"),
                    sentAt = payload.getLong("sentAt"),
                    senderDeviceId = payload.optString("senderDeviceId", ""),
                )
            )
            "receipt" -> RtcFrame.ReceiptFrame(
                RelayReceipt(
                    receiptId = payload.getString("receiptId"),
                    messageId = payload.getString("messageId"),
                    conversationId = payload.getString("conversationId"),
                    senderHandle = payload.getString("senderHandle"),
                    recipientHandle = payload.getString("recipientHandle"),
                    recipientDeviceId = payload.getString("recipientDeviceId"),
                    receiptType = payload.getString("receiptType"),
                    recordedAt = payload.getLong("recordedAt"),
                )
            )
            "read_cursor" -> RtcFrame.ReadCursorFrame(
                RelayReadCursor(
                    cursorId = payload.getString("cursorId"),
                    conversationId = payload.getString("conversationId"),
                    handle = payload.getString("handle"),
                    deviceId = payload.getString("deviceId"),
                    readThroughTimestamp = payload.getLong("readThroughTimestamp"),
                    recordedAt = payload.getLong("recordedAt"),
                )
            )
            else -> error("Unsupported RTC frame type: ${frame.optString("type")}")
        }
    }
}

private fun createOfferConstraints(iceRestart: Boolean): MediaConstraints = MediaConstraints().apply {
    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "false"))
    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", "false"))
    if (iceRestart) mandatory.add(MediaConstraints.KeyValuePair("IceRestart", "true"))
}

private suspend fun PeerConnection.createOfferAwait(constraints: MediaConstraints): SessionDescription =
    suspendCancellableCoroutine { continuation ->
        createOffer(object : SdpObserver {
            override fun onCreateSuccess(sessionDescription: SessionDescription?) {
                sessionDescription?.let(continuation::resume)
                    ?: continuation.resumeWithException(IllegalStateException("Offer creation returned null SDP"))
            }
            override fun onSetSuccess() = Unit
            override fun onCreateFailure(error: String?) = continuation.resumeWithException(IllegalStateException(error ?: "Offer creation failed"))
            override fun onSetFailure(error: String?) = Unit
        }, constraints)
    }

private suspend fun PeerConnection.createAnswerAwait(constraints: MediaConstraints): SessionDescription =
    suspendCancellableCoroutine { continuation ->
        createAnswer(object : SdpObserver {
            override fun onCreateSuccess(sessionDescription: SessionDescription?) {
                sessionDescription?.let(continuation::resume)
                    ?: continuation.resumeWithException(IllegalStateException("Answer creation returned null SDP"))
            }
            override fun onSetSuccess() = Unit
            override fun onCreateFailure(error: String?) = continuation.resumeWithException(IllegalStateException(error ?: "Answer creation failed"))
            override fun onSetFailure(error: String?) = Unit
        }, constraints)
    }

private suspend fun PeerConnection.setLocalDescriptionAwait(description: SessionDescription): Unit =
    suspendCancellableCoroutine { continuation ->
        setLocalDescription(object : SdpObserver {
            override fun onCreateSuccess(sessionDescription: SessionDescription?) = Unit
            override fun onSetSuccess() = continuation.resume(Unit)
            override fun onCreateFailure(error: String?) = Unit
            override fun onSetFailure(error: String?) = continuation.resumeWithException(IllegalStateException(error ?: "setLocalDescription failed"))
        }, description)
    }

private suspend fun PeerConnection.setRemoteDescriptionAwait(description: SessionDescription): Unit =
    suspendCancellableCoroutine { continuation ->
        setRemoteDescription(object : SdpObserver {
            override fun onCreateSuccess(sessionDescription: SessionDescription?) = Unit
            override fun onSetSuccess() = continuation.resume(Unit)
            override fun onCreateFailure(error: String?) = Unit
            override fun onSetFailure(error: String?) = continuation.resumeWithException(IllegalStateException(error ?: "setRemoteDescription failed"))
        }, description)
    }
