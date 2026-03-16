package com.qubee.messenger.transport

import org.json.JSONArray
import org.json.JSONObject

sealed interface ParsedRelayFrame {
    data class Challenge(val relaySessionId: String, val challenge: String) : ParsedRelayFrame
    data class Authenticated(val relaySessionId: String, val handle: String) : ParsedRelayFrame
    data class Envelope(val envelope: RelayEnvelope) : ParsedRelayFrame
    data class DeliveryAck(val messageId: String, val deliveredAt: Long) : ParsedRelayFrame
    data class PeerBundle(val peerHandle: String, val publicBundleBase64: String?) : ParsedRelayFrame
    data class ContactRequest(val request: RelayContactRequest) : ParsedRelayFrame
    data class HistorySync(val sync: RelayHistorySync) : ParsedRelayFrame
    data class Receipt(val receipt: RelayReceipt) : ParsedRelayFrame
    data class ReadCursor(val cursor: RelayReadCursor) : ParsedRelayFrame
    data class Signaling(val fromHandle: String, val toHandle: String, val signalType: String, val payload: String, val sentAt: Long) : ParsedRelayFrame
    data class Error(val message: String) : ParsedRelayFrame
    data object Ignored : ParsedRelayFrame
}

object RelayProtocol {
    fun helloJson(hello: RelayHello): String = JSONObject()
        .put("type", "hello")
        .put("handle", hello.handle)
        .put("deviceId", hello.deviceId)
        .put("displayName", hello.displayName)
        .put("publicBundleBase64", hello.publicBundleBase64)
        .put("identityFingerprint", hello.identityFingerprint)
        .toString()

    fun authenticateJson(proof: RelayAuthProof): String = JSONObject()
        .put("type", "authenticate")
        .put("handle", proof.handle)
        .put("relaySessionId", proof.relaySessionId)
        .put("challenge", proof.challenge)
        .put("publicBundleBase64", proof.publicBundleBase64)
        .put("identityFingerprint", proof.identityFingerprint)
        .put("signatureBase64", proof.signatureBase64)
        .toString()

    fun publishJson(envelope: RelayEnvelope): String = JSONObject()
        .put("type", "publish")
        .put("envelope", envelope.toJson())
        .toString()

    fun contactRequestJson(request: RelayContactRequest): String = JSONObject()
        .put("type", "contact_request")
        .put("request", request.toJson())
        .toString()

    fun receiptJson(receipt: RelayReceipt): String = JSONObject()
        .put("type", "receipt")
        .put("receipt", receipt.toJson())
        .toString()

    fun readCursorJson(cursor: RelayReadCursor): String = JSONObject()
        .put("type", "read_cursor")
        .put("cursor", cursor.toJson())
        .toString()

    fun requestPeerBundleJson(peerHandle: String): String = JSONObject()
        .put("type", "peer_bundle_request")
        .put("peerHandle", peerHandle)
        .toString()

    fun requestHistorySyncJson(since: Long): String = JSONObject()
        .put("type", "history_sync_request")
        .put("since", since)
        .toString()

    fun signalingJson(fromHandle: String, toHandle: String, signalType: String, payload: String, sentAt: Long): String = JSONObject()
        .put("type", "signaling")
        .put("fromHandle", fromHandle)
        .put("toHandle", toHandle)
        .put("signalType", signalType)
        .put("payload", payload)
        .put("sentAt", sentAt)
        .toString()

    fun parse(frameText: String): ParsedRelayFrame {
        val json = JSONObject(frameText)
        return when (json.optString("type")) {
            "challenge" -> ParsedRelayFrame.Challenge(
                relaySessionId = json.getString("relaySessionId"),
                challenge = json.getString("challenge"),
            )
            "authenticated" -> ParsedRelayFrame.Authenticated(
                relaySessionId = json.getString("relaySessionId"),
                handle = json.getString("handle"),
            )
            "delivery_ack" -> ParsedRelayFrame.DeliveryAck(
                messageId = json.getString("messageId"),
                deliveredAt = json.getLong("deliveredAt"),
            )
            "envelope" -> ParsedRelayFrame.Envelope(json.getJSONObject("envelope").toEnvelope())
            "peer_bundle_response" -> ParsedRelayFrame.PeerBundle(
                peerHandle = json.getString("peerHandle"),
                publicBundleBase64 = json.optString("publicBundleBase64").takeIf { it.isNotBlank() },
            )
            "contact_request" -> ParsedRelayFrame.ContactRequest(json.getJSONObject("request").toContactRequest())
            "history_sync_response" -> ParsedRelayFrame.HistorySync(json.toHistorySync())
            "receipt" -> ParsedRelayFrame.Receipt(json.getJSONObject("receipt").toReceipt())
            "read_cursor" -> ParsedRelayFrame.ReadCursor(json.getJSONObject("cursor").toReadCursor())
            "signaling" -> ParsedRelayFrame.Signaling(
                fromHandle = json.getString("fromHandle"),
                toHandle = json.getString("toHandle"),
                signalType = json.getString("signalType"),
                payload = json.getString("payload"),
                sentAt = json.getLong("sentAt"),
            )
            "error" -> ParsedRelayFrame.Error(json.optString("message", "Relay error"))
            else -> ParsedRelayFrame.Ignored
        }
    }

    private fun RelayEnvelope.toJson(): JSONObject = JSONObject()
        .put("messageId", messageId)
        .put("conversationId", conversationId)
        .put("senderHandle", senderHandle)
        .put("recipientHandle", recipientHandle)
        .put("sessionId", sessionId)
        .put("ciphertextBase64", ciphertextBase64)
        .put("algorithm", algorithm)
        .put("sentAt", sentAt)
        .put("senderDeviceId", senderDeviceId)

    private fun RelayContactRequest.toJson(): JSONObject = JSONObject()
        .put("requestId", requestId)
        .put("senderHandle", senderHandle)
        .put("recipientHandle", recipientHandle)
        .put("senderDisplayName", senderDisplayName)
        .put("publicBundleBase64", publicBundleBase64)
        .put("identityFingerprint", identityFingerprint)
        .put("sentAt", sentAt)

    private fun RelayReceipt.toJson(): JSONObject = JSONObject()
        .put("receiptId", receiptId)
        .put("messageId", messageId)
        .put("conversationId", conversationId)
        .put("senderHandle", senderHandle)
        .put("recipientHandle", recipientHandle)
        .put("recipientDeviceId", recipientDeviceId)
        .put("receiptType", receiptType)
        .put("recordedAt", recordedAt)

    private fun RelayReadCursor.toJson(): JSONObject = JSONObject()
        .put("cursorId", cursorId)
        .put("conversationId", conversationId)
        .put("handle", handle)
        .put("deviceId", deviceId)
        .put("readThroughTimestamp", readThroughTimestamp)
        .put("recordedAt", recordedAt)

    private fun JSONObject.toEnvelope(): RelayEnvelope = RelayEnvelope(
        messageId = getString("messageId"),
        conversationId = getString("conversationId"),
        senderHandle = getString("senderHandle"),
        recipientHandle = getString("recipientHandle"),
        sessionId = getString("sessionId"),
        ciphertextBase64 = getString("ciphertextBase64"),
        algorithm = getString("algorithm"),
        sentAt = getLong("sentAt"),
        senderDeviceId = optString("senderDeviceId", ""),
    )

    private fun JSONObject.toContactRequest(): RelayContactRequest = RelayContactRequest(
        requestId = getString("requestId"),
        senderHandle = getString("senderHandle"),
        recipientHandle = getString("recipientHandle"),
        senderDisplayName = getString("senderDisplayName"),
        publicBundleBase64 = getString("publicBundleBase64"),
        identityFingerprint = getString("identityFingerprint"),
        sentAt = getLong("sentAt"),
    )

    private fun JSONObject.toReceipt(): RelayReceipt = RelayReceipt(
        receiptId = getString("receiptId"),
        messageId = getString("messageId"),
        conversationId = getString("conversationId"),
        senderHandle = getString("senderHandle"),
        recipientHandle = getString("recipientHandle"),
        recipientDeviceId = getString("recipientDeviceId"),
        receiptType = getString("receiptType"),
        recordedAt = getLong("recordedAt"),
    )

    private fun JSONObject.toReadCursor(): RelayReadCursor = RelayReadCursor(
        cursorId = getString("cursorId"),
        conversationId = getString("conversationId"),
        handle = getString("handle"),
        deviceId = getString("deviceId"),
        readThroughTimestamp = getLong("readThroughTimestamp"),
        recordedAt = getLong("recordedAt"),
    )

    private fun JSONObject.toHistorySync(): RelayHistorySync = RelayHistorySync(
        relaySessionId = getString("relaySessionId"),
        syncedUntil = getLong("syncedUntil"),
        envelopes = getJSONArray("envelopes").toEnvelopeList(),
        contactRequests = getJSONArray("contactRequests").toContactRequestList(),
        receipts = optJSONArray("receipts")?.toReceiptList().orEmpty(),
        readCursors = optJSONArray("readCursors")?.toReadCursorList().orEmpty(),
    )

    private fun JSONArray.toEnvelopeList(): List<RelayEnvelope> = buildList {
        for (index in 0 until length()) add(getJSONObject(index).toEnvelope())
    }

    private fun JSONArray.toContactRequestList(): List<RelayContactRequest> = buildList {
        for (index in 0 until length()) add(getJSONObject(index).toContactRequest())
    }

    private fun JSONArray.toReceiptList(): List<RelayReceipt> = buildList {
        for (index in 0 until length()) add(getJSONObject(index).toReceipt())
    }

    private fun JSONArray.toReadCursorList(): List<RelayReadCursor> = buildList {
        for (index in 0 until length()) add(getJSONObject(index).toReadCursor())
    }
}
