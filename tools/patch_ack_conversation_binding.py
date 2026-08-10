from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


# DAO: wire id is not sufficient authorization. Bind acknowledgement lookup to
# the conversation id supplied by the authenticated protocol context.
replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''    @Query("SELECT * FROM messages WHERE wireId = :wireId LIMIT 1")\n    abstract suspend fun getMessageByWireId(wireId: String): Message?\n''',
    '''    @Query("SELECT * FROM messages WHERE wireId = :wireId LIMIT 1")\n    abstract suspend fun getMessageByWireId(wireId: String): Message?\n\n    @Query(\n        "SELECT * FROM messages " +\n            "WHERE wireId = :wireId AND conversationId = :conversationId LIMIT 1"\n    )\n    abstract suspend fun getMessageByWireIdForConversation(\n        wireId: String,\n        conversationId: String,\n    ): Message?\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''    open suspend fun applyAckTransactional(\n        wireId: String,\n        ackerIdHex: String,\n    ): ApplyAckResult {\n        val row = getMessageByWireId(wireId) ?: return ApplyAckResult.NotFound\n''',
    '''    open suspend fun applyAckTransactional(\n        wireId: String,\n        ackerIdHex: String,\n        expectedConversationId: String,\n    ): ApplyAckResult {\n        val row = getMessageByWireIdForConversation(wireId, expectedConversationId)\n            ?: return ApplyAckResult.NotFound\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''     * Atomically read + update the row matched by `wireId` to record\n     * `ackerIdHex` as a recipient that ack'd this message. Runs the\n''',
    '''     * Atomically read + update the row matched by both `wireId` and the\n     * authenticated protocol context's `expectedConversationId`, then record\n     * `ackerIdHex` as a recipient that ack'd this message. Runs the\n''',
)

# Repository: make conversation binding mandatory at the API boundary.
replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/MessageRepository.kt",
    '''    suspend fun applyAck(wireId: String, ackerIdHex: String): Boolean =\n        when (messageDao.applyAckTransactional(wireId, ackerIdHex)) {\n''',
    '''    suspend fun applyAck(\n        wireId: String,\n        ackerIdHex: String,\n        expectedConversationId: String,\n    ): Boolean =\n        when (messageDao.applyAckTransactional(wireId, ackerIdHex, expectedConversationId)) {\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/MessageRepository.kt",
    '''     * Apply an inbound `MessageAck` to the local outbound row.\n     *\n     * Delegates to [MessageDao.applyAckTransactional] so the\n''',
    '''     * Apply an authenticated acknowledgement to the local outbound row.\n     * `expectedConversationId` is mandatory: a wire id alone is correlation,\n     * not authorization. Direct receipts derive the conversation from the\n     * ratchet-authenticated sender; group receipts use their signed group id.\n     *\n     * Delegates to [MessageDao.applyAckTransactional] so the\n''',
)

# Conversation repository: resolve only; never mint a new conversation merely
# because an ACK arrived.
replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/ConversationRepository.kt",
    '''    suspend fun getOrCreateConversationId(contactId: String): String {\n        val existing = conversationDao.getConversationsByType(ConversationType.DIRECT)\n            .firstOrNull { it.participants.contains(contactId) }\n        if (existing != null) return existing.id\n''',
    '''    suspend fun findDirectConversationId(contactId: String): String? =\n        conversationDao.getConversationsByType(ConversationType.DIRECT)\n            .firstOrNull { it.participants.contains(contactId) }\n            ?.id\n\n    suspend fun getOrCreateConversationId(contactId: String): String {\n        val existingId = findDirectConversationId(contactId)\n        if (existingId != null) return existingId\n''',
)

# Direct ACK: ratchet-authenticated sender must map to the same direct
# conversation as the row. Fail closed if the contact/conversation has vanished.
replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''                    } else {\n                        val applied = messageRepository.applyAck(ackedWireId, senderIdentityHex)\n                        if (!applied) {\n                            Timber.d("Ignored direct ack for unknown wireId=%s", ackedWireId)\n                        }\n                    }\n''',
    '''                    } else {\n                        val contact = contactRepository.getContactByIdentityId(senderIdentityHex)\n                        val participantId = contact?.id ?: senderIdentityHex\n                        val directConversationId =\n                            conversationRepository.findDirectConversationId(participantId)\n                        if (directConversationId == null) {\n                            Timber.w(\n                                "Ignored direct ack from %s: no matching direct conversation",\n                                senderIdentityHex,\n                            )\n                        } else {\n                            val applied = messageRepository.applyAck(\n                                ackedWireId,\n                                senderIdentityHex,\n                                directConversationId,\n                            )\n                            if (!applied) {\n                                Timber.d(\n                                    "Ignored direct ack for wireId=%s outside conversation=%s",\n                                    ackedWireId,\n                                    directConversationId,\n                                )\n                            }\n                        }\n                    }\n''',
)

# Group ACK: signed group id is the authenticated conversation context.
replace_once(
    "app/src/main/java/com/qubee/messenger/service/MessageService.kt",
    '''                val applied = messageRepository.applyAck(messageIdHex, ackerIdHex)\n                if (!applied) {\n                    Timber.d("Ignored ack for unknown wireId=%s", messageIdHex)\n                }\n''',
    '''                val applied = messageRepository.applyAck(\n                    messageIdHex,\n                    ackerIdHex,\n                    groupIdHex,\n                )\n                if (!applied) {\n                    Timber.d(\n                        "Ignored ack for wireId=%s outside group=%s",\n                        messageIdHex,\n                        groupIdHex,\n                    )\n                }\n''',
)

# Instrumented regression: same wire id in a different conversation must not be
# authorized by an ACK for this conversation, and a correctly bound ACK retires
# the intended row only.
replace_once(
    "app/src/androidTest/java/com/qubee/messenger/data/repository/database/MessageDaoInstrumentedTest.kt",
    '''    @Test\n    fun inbound_direct_receipt_cache_roundtrips_without_entering_retry_queue() = runTest {\n''',
    '''    @Test\n    fun ack_is_bound_to_expected_conversation_before_retry_is_retired() = runTest {\n        val sharedWireId = "abababababababababababababababab"\n        val intended = Message(\n            id = "bound-ack-1",\n            conversationId = "direct-alice",\n            senderId = "me",\n            status = MessageStatus.SENT,\n            isFromMe = true,\n            wireId = sharedWireId,\n            wireBytes = byteArrayOf(1, 2, 3),\n            nextRetryAt = 10L,\n        )\n        dao.insertMessage(intended)\n\n        assertTrue(\n            dao.applyAckTransactional(\n                sharedWireId,\n                "alice-identity",\n                "direct-alice",\n            ) is com.qubee.messenger.data.repository.database.dao.ApplyAckResult.Applied,\n        )\n        val after = dao.getMessageById(intended.id)!!\n        assertEquals(MessageStatus.DELIVERED, after.status)\n        assertNull(after.wireBytes)\n        assertNull(after.nextRetryAt)\n\n        val wrongConversation = Message(\n            id = "bound-ack-2",\n            conversationId = "direct-bob",\n            senderId = "me",\n            status = MessageStatus.SENT,\n            isFromMe = true,\n            wireId = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",\n            wireBytes = byteArrayOf(4, 5, 6),\n            nextRetryAt = 20L,\n        )\n        dao.insertMessage(wrongConversation)\n        val rejected = dao.applyAckTransactional(\n            wrongConversation.wireId!!,\n            "alice-identity",\n            "direct-alice",\n        )\n        assertTrue(\n            rejected is com.qubee.messenger.data.repository.database.dao.ApplyAckResult.NotFound,\n        )\n        val untouched = dao.getMessageById(wrongConversation.id)!!\n        assertEquals(MessageStatus.SENT, untouched.status)\n        assertArrayEquals(byteArrayOf(4, 5, 6), untouched.wireBytes)\n        assertEquals(20L, untouched.nextRetryAt)\n    }\n\n    @Test\n    fun inbound_direct_receipt_cache_roundtrips_without_entering_retry_queue() = runTest {\n''',
)

print("ack conversation-binding patch applied")
