package com.qubee.messenger.network.p2p

import org.json.JSONObject

sealed interface WebRtcBootstrapSignal {
    val fromHandle: String
    val fromDeviceId: String
    val toHandle: String
    val sentAt: Long

    data class Offer(
        override val fromHandle: String,
        override val fromDeviceId: String,
        override val toHandle: String,
        override val sentAt: Long,
        val sdp: String,
        val bootstrapToken: String? = null,
        val preferredBootstrap: String? = null,
        val turnPolicy: TurnPolicy? = null,
    ) : WebRtcBootstrapSignal

    data class Answer(
        override val fromHandle: String,
        override val fromDeviceId: String,
        override val toHandle: String,
        override val sentAt: Long,
        val sdp: String,
        val bootstrapToken: String? = null,
        val preferredBootstrap: String? = null,
        val turnPolicy: TurnPolicy? = null,
    ) : WebRtcBootstrapSignal

    data class IceCandidateSignal(
        override val fromHandle: String,
        override val fromDeviceId: String,
        override val toHandle: String,
        override val sentAt: Long,
        val sdpMid: String?,
        val sdpMLineIndex: Int,
        val candidate: String,
        val bootstrapToken: String? = null,
    ) : WebRtcBootstrapSignal
}

object WebRtcBootstrapCodec {
    fun encode(signal: WebRtcBootstrapSignal): SignalingMessage {
        val payload = when (signal) {
            is WebRtcBootstrapSignal.Offer -> JSONObject()
                .put("kind", "offer")
                .put("fromHandle", signal.fromHandle)
                .put("fromDeviceId", signal.fromDeviceId)
                .put("toHandle", signal.toHandle)
                .put("sentAt", signal.sentAt)
                .put("sdp", signal.sdp)
                .put("bootstrapToken", signal.bootstrapToken)
                .put("preferredBootstrap", signal.preferredBootstrap)
                .put("turnPolicy", signal.turnPolicy?.let(TurnPolicyCodec::encode))
            is WebRtcBootstrapSignal.Answer -> JSONObject()
                .put("kind", "answer")
                .put("fromHandle", signal.fromHandle)
                .put("fromDeviceId", signal.fromDeviceId)
                .put("toHandle", signal.toHandle)
                .put("sentAt", signal.sentAt)
                .put("sdp", signal.sdp)
                .put("bootstrapToken", signal.bootstrapToken)
                .put("preferredBootstrap", signal.preferredBootstrap)
                .put("turnPolicy", signal.turnPolicy?.let(TurnPolicyCodec::encode))
            is WebRtcBootstrapSignal.IceCandidateSignal -> JSONObject()
                .put("kind", "ice")
                .put("fromHandle", signal.fromHandle)
                .put("fromDeviceId", signal.fromDeviceId)
                .put("toHandle", signal.toHandle)
                .put("sentAt", signal.sentAt)
                .put("sdpMid", signal.sdpMid)
                .put("sdpMLineIndex", signal.sdpMLineIndex)
                .put("candidate", signal.candidate)
                .put("bootstrapToken", signal.bootstrapToken)
        }
        return SignalingMessage(
            type = when (signal) {
                is WebRtcBootstrapSignal.Offer -> "sdp_offer"
                is WebRtcBootstrapSignal.Answer -> "sdp_answer"
                is WebRtcBootstrapSignal.IceCandidateSignal -> "ice_candidate"
            },
            peerHandle = signal.toHandle,
            payload = payload.toString(),
            sentAt = signal.sentAt,
        )
    }

    fun decode(message: SignalingMessage): WebRtcBootstrapSignal? {
        val json = JSONObject(message.payload)
        val fromHandle = json.getString("fromHandle")
        val fromDeviceId = json.optString("fromDeviceId", "")
        val toHandle = json.getString("toHandle")
        val sentAt = json.optLong("sentAt", message.sentAt)
        return when (message.type) {
            "sdp_offer" -> WebRtcBootstrapSignal.Offer(
                fromHandle = fromHandle,
                fromDeviceId = fromDeviceId,
                toHandle = toHandle,
                sentAt = sentAt,
                sdp = json.getString("sdp"),
                bootstrapToken = json.optString("bootstrapToken").takeIf { it.isNotBlank() },
                preferredBootstrap = json.optString("preferredBootstrap").takeIf { it.isNotBlank() },
                turnPolicy = TurnPolicyCodec.decode(json.optJSONObject("turnPolicy")),
            )
            "sdp_answer" -> WebRtcBootstrapSignal.Answer(
                fromHandle = fromHandle,
                fromDeviceId = fromDeviceId,
                toHandle = toHandle,
                sentAt = sentAt,
                sdp = json.getString("sdp"),
                bootstrapToken = json.optString("bootstrapToken").takeIf { it.isNotBlank() },
                preferredBootstrap = json.optString("preferredBootstrap").takeIf { it.isNotBlank() },
                turnPolicy = TurnPolicyCodec.decode(json.optJSONObject("turnPolicy")),
            )
            "ice_candidate" -> WebRtcBootstrapSignal.IceCandidateSignal(
                fromHandle = fromHandle,
                fromDeviceId = fromDeviceId,
                toHandle = toHandle,
                sentAt = sentAt,
                sdpMid = json.optString("sdpMid").takeIf { it.isNotBlank() },
                sdpMLineIndex = json.getInt("sdpMLineIndex"),
                candidate = json.getString("candidate"),
                bootstrapToken = json.optString("bootstrapToken").takeIf { it.isNotBlank() },
            )
            else -> null
        }
    }
}
