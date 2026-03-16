package com.qubee.messenger.transport

object RelayEnvelopeValidator {
    fun isValid(envelope: RelayEnvelope): Boolean {
        return envelope.messageId.isNotBlank() &&
            envelope.conversationId.isNotBlank() &&
            envelope.senderHandle.isNotBlank() &&
            envelope.recipientHandle.isNotBlank() &&
            envelope.sessionId.isNotBlank() &&
            envelope.ciphertextBase64.isNotBlank() &&
            envelope.algorithm.isNotBlank() &&
            envelope.sentAt > 0L
    }
}
