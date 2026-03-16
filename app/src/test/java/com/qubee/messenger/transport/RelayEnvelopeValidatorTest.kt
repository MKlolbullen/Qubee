package com.qubee.messenger.transport

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayEnvelopeValidatorTest {
    @Test
    fun validEnvelopePassesValidation() {
        val envelope = RelayEnvelope(
            messageId = "m-1",
            conversationId = "c-1",
            senderHandle = "alice",
            recipientHandle = "bob",
            sessionId = "s-1",
            ciphertextBase64 = "Y2lwaGVy",
            algorithm = "xchacha20poly1305",
            sentAt = 123L,
            senderDeviceId = "device-a",
        )

        assertTrue(RelayEnvelopeValidator.isValid(envelope))
    }

    @Test
    fun envelopeMissingCriticalFieldsFailsValidation() {
        val envelope = RelayEnvelope(
            messageId = "",
            conversationId = "c-1",
            senderHandle = "alice",
            recipientHandle = "bob",
            sessionId = "",
            ciphertextBase64 = "",
            algorithm = "",
            sentAt = 0L,
            senderDeviceId = "",
        )

        assertFalse(RelayEnvelopeValidator.isValid(envelope))
    }
}
