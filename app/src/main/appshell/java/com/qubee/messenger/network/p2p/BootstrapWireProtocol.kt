package com.qubee.messenger.network.p2p

import org.json.JSONObject

internal sealed interface BootstrapWireFrame {
    data class Hello(
        val targetToken: String,
        val fromHandle: String,
        val fromDeviceId: String,
        val fromTokenHash: String,
        val transport: String,
    ) : BootstrapWireFrame

    data class HelloAck(
        val fromHandle: String,
        val fromDeviceId: String,
        val fromTokenHash: String,
        val transport: String,
    ) : BootstrapWireFrame

    data class Signal(val message: SignalingMessage) : BootstrapWireFrame
}

internal object BootstrapWireCodec {
    fun encode(frame: BootstrapWireFrame): String = when (frame) {
        is BootstrapWireFrame.Hello -> JSONObject()
            .put("kind", "hello")
            .put("targetToken", frame.targetToken)
            .put("fromHandle", frame.fromHandle)
            .put("fromDeviceId", frame.fromDeviceId)
            .put("fromTokenHash", frame.fromTokenHash)
            .put("transport", frame.transport)
            .toString()
        is BootstrapWireFrame.HelloAck -> JSONObject()
            .put("kind", "hello_ack")
            .put("fromHandle", frame.fromHandle)
            .put("fromDeviceId", frame.fromDeviceId)
            .put("fromTokenHash", frame.fromTokenHash)
            .put("transport", frame.transport)
            .toString()
        is BootstrapWireFrame.Signal -> JSONObject()
            .put("kind", "signal")
            .put("type", frame.message.type)
            .put("peerHandle", frame.message.peerHandle)
            .put("payload", frame.message.payload)
            .put("sentAt", frame.message.sentAt)
            .toString()
    }

    fun encodeLine(frame: BootstrapWireFrame): String = encode(frame) + "\n"

    fun decode(raw: String): BootstrapWireFrame {
        val json = JSONObject(raw)
        return when (json.getString("kind")) {
            "hello" -> BootstrapWireFrame.Hello(
                targetToken = json.optString("targetToken"),
                fromHandle = json.getString("fromHandle"),
                fromDeviceId = json.optString("fromDeviceId"),
                fromTokenHash = json.optString("fromTokenHash"),
                transport = json.optString("transport", "unknown"),
            )
            "hello_ack" -> BootstrapWireFrame.HelloAck(
                fromHandle = json.getString("fromHandle"),
                fromDeviceId = json.optString("fromDeviceId"),
                fromTokenHash = json.optString("fromTokenHash"),
                transport = json.optString("transport", "unknown"),
            )
            "signal" -> BootstrapWireFrame.Signal(
                SignalingMessage(
                    type = json.getString("type"),
                    peerHandle = json.getString("peerHandle"),
                    payload = json.getString("payload"),
                    sentAt = json.optLong("sentAt", System.currentTimeMillis()),
                )
            )
            else -> error("Unsupported bootstrap frame kind: ${json.optString("kind")}")
        }
    }
}
