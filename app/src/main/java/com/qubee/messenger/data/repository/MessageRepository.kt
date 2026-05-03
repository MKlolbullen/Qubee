package com.qubee.messenger.data.repository

import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageWithSender
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import kotlinx.coroutines.flow.Flow
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

// Real Room-backed implementation — rev-3 priority 6.
@Singleton
class MessageRepository @Inject constructor(
    private val messageDao: MessageDao,
    private val conversationDao: ConversationDao,
) {

    /// Wire-compat alias kept for the rev-2 stub callers that named
    /// the conversation a "session". `ChatViewModel` and
    /// `MessageService` will migrate to `getMessagesForConversation`
    /// in the next batch.
    fun getMessagesForSession(sessionId: String): Flow<List<MessageWithSender>> =
        messageDao.getMessagesWithSenderForConversation(sessionId)

    fun getMessagesForConversation(conversationId: String): Flow<List<MessageWithSender>> =
        messageDao.getMessagesWithSenderForConversation(conversationId)

    fun getTotalUnreadMessageCount(): Flow<Int> = messageDao.getTotalUnreadMessageCount()

    suspend fun saveMessage(message: Message) {
        messageDao.insertMessage(message)
        conversationDao.updateLastMessage(
            conversationId = message.conversationId,
            messageId = message.id,
            timestamp = message.timestamp,
        )
    }

    suspend fun updateMessageStatus(messageId: String, status: MessageStatus) {
        messageDao.updateMessageStatus(messageId, status)
    }

    suspend fun markAllMessagesAsRead(conversationId: String) {
        messageDao.markAllMessagesAsRead(conversationId)
    }

    suspend fun deleteAllMessagesForConversation(conversationId: String) {
        messageDao.deleteAllMessagesForConversation(conversationId)
    }

    suspend fun cleanupExpiredMessages(): Int {
        val nowSeconds = System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(1)
        return messageDao.deleteExpiredMessages(nowSeconds)
    }
}
