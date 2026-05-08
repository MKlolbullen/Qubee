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

    /**
     * Stamp an outbound row with the canonical wire-level message
     * id immediately after encryption succeeds. Inbound `MessageAck`
     * frames look up by this id; rows without one stay
     * uncorrelatable to acks (and `applyAck` returns false).
     */
    suspend fun updateWireId(messageId: String, wireId: String) {
        val row = messageDao.getMessageById(messageId) ?: return
        if (row.wireId == wireId) return
        messageDao.updateMessage(row.copy(wireId = wireId))
    }

    /**
     * Apply an inbound `MessageAck` to the local outbound row.
     *
     * Looks up the row by `wireId` (set at send time via
     * `nativeExtractMessageId`). If we don't recognise the id —
     * because the ack is for a message someone else sent, or
     * because pre-this-feature rows lack a `wireId` — the call is
     * a no-op.
     *
     * Otherwise: dedupe the acker against the existing
     * `deliveredAckers` list (set semantics — a recipient who
     * resends an ack only counts once) and bump the row's status
     * to `DELIVERED` on the first ack arrival. Late ack-after-read
     * is ignored (status doesn't move backwards from `READ`).
     *
     * Returns `true` when the row was found and `false` otherwise,
     * mostly so callers can log "ignored ack for unknown id" at
     * debug level without surfacing it to the user.
     */
    suspend fun applyAck(wireId: String, ackerIdHex: String): Boolean {
        val row = messageDao.getMessageByWireId(wireId) ?: return false
        if (row.deliveredAckers.contains(ackerIdHex)) {
            return true // idempotent — caller already accounted for
        }
        val updated = row.copy(
            deliveredAckers = row.deliveredAckers + ackerIdHex,
            status = if (row.status == MessageStatus.READ) {
                row.status
            } else {
                MessageStatus.DELIVERED
            },
        )
        messageDao.updateMessage(updated)
        return true
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
