from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


# Cache the first encrypted receipt on the inbound message row. Inbound rows are
# excluded by getRetryableOutbound(isFromMe = 1), so reusing wireBytes here does
# not enqueue receipts in the normal outbound retry loop.
replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''    abstract suspend fun getMessageByWireId(wireId: String): Message?\n\n    /// Outbound rows the offline-retry loop should re-publish: `SENT` or\n''',
    '''    abstract suspend fun getMessageByWireId(wireId: String): Message?\n\n    /// Persist the exact encrypted direct receipt produced for an inbound text.\n    /// Duplicate delivery of the original ciphertext re-sends these same bytes\n    /// instead of encrypting another ACK and advancing the send ratchet again.\n    /// The isFromMe predicate prevents accidental writes to outbound retry rows.\n    @Query(\n        "UPDATE messages SET wireBytes = :receiptWire " +\n            "WHERE id = :messageId AND isFromMe = 0"\n    )\n    abstract suspend fun cacheInboundDirectReceipt(messageId: String, receiptWire: ByteArray)\n\n    /// Outbound rows the offline-retry loop should re-publish: `SENT` or\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/MessageRepository.kt",
    '''    suspend fun getMessageByWireId(wireId: String): Message? =\n        messageDao.getMessageByWireId(wireId)\n\n    /**\n''',
    '''    suspend fun getMessageByWireId(wireId: String): Message? =\n        messageDao.getMessageByWireId(wireId)\n\n    suspend fun cacheInboundDirectReceipt(messageId: String, receiptWire: ByteArray) {\n        messageDao.cacheInboundDirectReceipt(messageId, receiptWire)\n    }\n\n    /**\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/model/Models.kt",
    '''    /// The raw wire bytes (sealed outer envelope) produced by the\n    /// first encrypt. Kept around so the offline-retry loop can\n    /// re-publish *the same bytes* — preserving the row's `wireId`\n    /// so any late-arriving `MessageAck` still correlates back to\n    /// this row. Cleared once the first ack arrives; null on rows\n    /// that don't need retry (DELIVERED / READ already, or the\n    /// retry budget is exhausted).\n''',
    '''    /// Durable opaque wire bytes associated with this row. For outbound\n    /// messages this is the first encrypted frame, retained so retries re-send\n    /// exactly the same bytes and preserve `wireId`. For inbound direct texts\n    /// it caches the first encrypted delivery-receipt frame: duplicate text\n    /// delivery re-sends that exact receipt rather than advancing our send\n    /// ratchet again. `getRetryableOutbound` is scoped to `isFromMe = 1`, so\n    /// inbound receipt caches never enter the normal retry queue. Outbound bytes\n    /// are cleared when the first receipt lands; inbound caches live with the\n    /// message row and disappear when that message is deleted/expired.\n''',
)

# Duplicate exact text: re-send cached ACK wire. Only if a crash happened after
# plaintext persistence but before ACK construction do we create/cache one now.
replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''            val prior = messageRepository.getMessageByWireId(directMessageId)\n            if (prior != null && !prior.isFromMe) {\n                val senderIdentityHex = qubeeManager.inspectDirectMessageSender(data)\n                if (!senderIdentityHex.isNullOrBlank()) {\n                    sendDirectDeliveryAck(senderIdentityHex, directMessageId)\n                } else {\n                    Timber.w("Cannot re-ack direct replay: sender selector is unresolved")\n                }\n                return true\n            }\n''',
    '''            val prior = messageRepository.getMessageByWireId(directMessageId)\n            if (prior != null && !prior.isFromMe) {\n                sendOrReplayDirectDeliveryAck(\n                    inboundMessage = prior,\n                    originalWire = data,\n                    messageIdHex = directMessageId,\n                    authenticatedSenderIdentityHex = null,\n                )\n                return true\n            }\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''                    messageRepository.saveMessage(\n                        Message(\n                            id = UUID.randomUUID().toString(),\n                            conversationId = conversationId,\n                            senderId = routedSenderId,\n                            content = result.optString("text"),\n                            contentType = MessageType.TEXT,\n                            timestamp = System.currentTimeMillis(),\n                            status = MessageStatus.DELIVERED,\n                            isFromMe = false,\n                            wireId = directMessageId,\n                        ),\n                    )\n                    if (contact != null) {\n''',
    '''                    val inboundMessage = Message(\n                        id = UUID.randomUUID().toString(),\n                        conversationId = conversationId,\n                        senderId = routedSenderId,\n                        content = result.optString("text"),\n                        contentType = MessageType.TEXT,\n                        timestamp = System.currentTimeMillis(),\n                        status = MessageStatus.DELIVERED,\n                        isFromMe = false,\n                        wireId = directMessageId,\n                    )\n                    messageRepository.saveMessage(inboundMessage)\n                    if (contact != null) {\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''                    // Receipt only after the plaintext is durably persisted. If\n                    // this send is lost, the sender retries the same ciphertext\n                    // and the prior-wireId branch above emits a fresh receipt.\n                    sendDirectDeliveryAck(senderIdentityHex, directMessageId)\n''',
    '''                    // Receipt only after the plaintext is durably persisted. Cache\n                    // the exact encrypted receipt before transmit; if it is lost, an\n                    // exact text retry re-sends the same receipt bytes without advancing\n                    // our send ratchet a second time.\n                    sendOrReplayDirectDeliveryAck(\n                        inboundMessage = inboundMessage,\n                        originalWire = data,\n                        messageIdHex = directMessageId,\n                        authenticatedSenderIdentityHex = senderIdentityHex,\n                    )\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''    private suspend fun sendDirectDeliveryAck(recipientIdentityHex: String, messageIdHex: String) {\n        val ackWire = qubeeManager.createDirectMessageAck(recipientIdentityHex, messageIdHex)\n        if (ackWire == null) {\n            Timber.w("Could not create direct delivery ack for %s", messageIdHex)\n            return\n        }\n        // Rust owns QUBEE_DMS routing from the frame's opaque recipient\n        // selector. Empty compatibility hint makes that authority explicit.\n        if (!qubeeManager.sendP2PMessage("", ackWire)) {\n            Timber.d("Direct delivery ack enqueue failed for %s; sender retry will solicit another", messageIdHex)\n        }\n    }\n''',
    '''    private suspend fun sendOrReplayDirectDeliveryAck(\n        inboundMessage: Message,\n        originalWire: ByteArray,\n        messageIdHex: String,\n        authenticatedSenderIdentityHex: String?,\n    ) {\n        var ackWire = inboundMessage.wireBytes\n        if (ackWire == null) {\n            // Normal first delivery already has an authenticated sender from the\n            // successful decrypt. The duplicate-after-crash path may only have the\n            // durable original wire, so resolve its opaque sender selector against\n            // Rust's signature-verified peer cache.\n            val recipientIdentityHex = authenticatedSenderIdentityHex\n                ?.takeIf { it.isNotBlank() }\n                ?: qubeeManager.inspectDirectMessageSender(originalWire)\n            if (recipientIdentityHex.isNullOrBlank()) {\n                Timber.w("Cannot create direct receipt: sender selector is unresolved")\n                return\n            }\n            ackWire = qubeeManager.createDirectMessageAck(recipientIdentityHex, messageIdHex)\n            if (ackWire == null) {\n                Timber.w("Could not create direct delivery ack for %s", messageIdHex)\n                return\n            }\n            // Persist before transmit. A crash or an active replay after this point\n            // can only cause this exact receipt ciphertext to be re-published; it\n            // cannot repeatedly advance our Double Ratchet send chain.\n            messageRepository.cacheInboundDirectReceipt(inboundMessage.id, ackWire)\n        }\n\n        // Rust owns QUBEE_DMS routing from the frame's opaque recipient selector.\n        // Empty compatibility hint makes that authority explicit.\n        if (!qubeeManager.sendP2PMessage("", ackWire)) {\n            Timber.d("Direct delivery ack enqueue failed for %s; exact-text retry can replay it", messageIdHex)\n        }\n    }\n''',
)

# DAO regression: cached inbound receipt bytes must round-trip but never become
# an outbound retry candidate.
replace_once(
    "app/src/androidTest/java/com/qubee/messenger/data/repository/database/MessageDaoInstrumentedTest.kt",
    'import org.junit.Assert.assertEquals\n',
    'import org.junit.Assert.assertArrayEquals\nimport org.junit.Assert.assertEquals\n',
)
replace_once(
    "app/src/androidTest/java/com/qubee/messenger/data/repository/database/MessageDaoInstrumentedTest.kt",
    '''    @Test\n    fun rows_without_wireId_are_invisible_to_wireId_lookup() = runTest {\n''',
    '''    @Test\n    fun inbound_direct_receipt_cache_roundtrips_without_entering_retry_queue() = runTest {\n        val inbound = Message(\n            id = "inbound-direct-1",\n            conversationId = "direct-1",\n            senderId = "peer",\n            content = "accepted text",\n            contentType = MessageType.TEXT,\n            timestamp = 4_000L,\n            status = MessageStatus.DELIVERED,\n            isFromMe = false,\n            wireId = "33333333333333333333333333333333",\n        )\n        dao.insertMessage(inbound)\n        val receiptWire = byteArrayOf(0x51, 0x55, 0x42, 0x45, 0x45)\n        dao.cacheInboundDirectReceipt(inbound.id, receiptWire)\n\n        val stored = dao.getMessageById(inbound.id)!!\n        assertArrayEquals(receiptWire, stored.wireBytes)\n        assertTrue(\n            "inbound receipt cache must never be selected by the outbound retry query",\n            dao.getRetryableOutbound(\n                now = Long.MAX_VALUE,\n                maxAttempts = 99,\n                limit = 100,\n            ).none { it.id == inbound.id },\n        )\n    }\n\n    @Test\n    fun rows_without_wireId_are_invisible_to_wireId_lookup() = runTest {\n''',
)

print("replay-safe direct ACK patch applied")
