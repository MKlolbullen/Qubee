package com.qubee.messenger.data.repository

import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageWithSender
import com.qubee.messenger.data.repository.database.dao.ApplyAckResult
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import kotlinx.coroutines.flow.Flow
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

// Real Room-backed implementation — rev-3 priority 6.
@Singleton
class MessageRepository @Inject constructor(
    // dagger.Lazy: defers SQLCipher open to first DAO use so the
    // app-lock gate can hold DB access until unlock (no-op when Screen
    // Lock is off).
    private val messageDaoLazy: dagger.Lazy<MessageDao>,
    private val conversationDaoLazy: dagger.Lazy<ConversationDao>,
) {
    private val messageDao get() = messageDaoLazy.get()
    private val conversationDao get() = conversationDaoLazy.get()

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

    suspend fun getMessageByWireId(wireId: String): Message? =
        messageDao.getMessageByWireId(wireId)

    /**
     * Return outbound rows whose retry timer has fired and whose
     * budget hasn't been exhausted. Used by `MessageService`'s
     * offline-retry loop.
     */
    suspend fun dueForRetry(now: Long, maxAttempts: Int, limit: Int): List<Message> =
        messageDao.getRetryableOutbound(now = now, maxAttempts = maxAttempts, limit = limit)

    /**
     * Crash-consistency recovery: surface any outbound row orphaned in
     * `PREPARED` by a previous process death as `FAILED` (text preserved,
     * resendable) rather than losing it silently. Returns how many were
     * recovered. Safe to call once at process start — a genuinely
     * in-flight PREPARED row only exists within a single send coroutine,
     * which transitions it before this runs.
     */
    suspend fun recoverStalePreparedOutbound(): Int =
        messageDao.failStalePreparedOutbound()

    /**
     * Crash-consistency recovery for the transmit window: promote any
     * outbound row orphaned in `SENDING` (ciphertext durable, publish
     * unconfirmed) to `SENT` so the offline-retry loop reclaims and
     * re-publishes it, rather than leaving it queued forever. Returns how
     * many were recovered.
     */
    suspend fun recoverOrphanedSendingOutbound(): Int =
        messageDao.recoverOrphanedSendingOutbound()

    /**
     * Re-stamp a row after a retry tick. Pass `nextRetryAt = null`
     * to retire the row (budget exhausted).
     */
    suspend fun scheduleNextRetry(
        messageId: String,
        attempt: Int,
        nextRetryAt: Long?,
    ) {
        messageDao.updateRetrySchedule(messageId, attempt, nextRetryAt)
    }

    /**
     * Apply an inbound `MessageAck` to the local outbound row.
     *
     * Delegates to [MessageDao.applyAckTransactional] so the
     * read-modify-write happens inside one SQLite transaction.
     * Two acks from different recipients arriving simultaneously
     * can't lose one to a stale-read race; both end up in
     * `deliveredAckers`.
     *
     * Returns `true` when the row was found (whether the ack was
     * freshly applied or was an idempotent duplicate) and `false`
     * when no row carried this `wireId` — caller logs the latter
     * at debug level without surfacing to the user.
     */
    suspend fun applyAck(wireId: String, ackerIdHex: String): Boolean =
        when (messageDao.applyAckTransactional(wireId, ackerIdHex)) {
            is ApplyAckResult.NotFound -> false
            is ApplyAckResult.AlreadyApplied,
            is ApplyAckResult.Applied -> true
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
