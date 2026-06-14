package com.qubee.messenger.data.repository.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageWithSender
import kotlinx.coroutines.flow.Flow

@Dao
abstract class MessageDao {

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId AND isDeleted = 0 ORDER BY timestamp ASC")
    abstract fun getMessagesForConversation(conversationId: String): Flow<List<Message>>

    // Joins the sender's display name out of `contacts` so the chat
    // surface doesn't need a per-row contact lookup.
    @Query(
        """
        SELECT m.*,
               COALESCE(c.displayName, m.senderId) as senderName
        FROM messages m
        LEFT JOIN contacts c ON c.id = m.senderId
        WHERE m.conversationId = :conversationId AND m.isDeleted = 0
        ORDER BY m.timestamp ASC
        """
    )
    abstract fun getMessagesWithSenderForConversation(conversationId: String): Flow<List<MessageWithSender>>

    @Query("SELECT * FROM messages WHERE id = :messageId")
    abstract suspend fun getMessageById(messageId: String): Message?

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp DESC LIMIT 1")
    abstract suspend fun getLastMessageForConversation(conversationId: String): Message?

    @Query("SELECT COUNT(*) FROM messages WHERE conversationId = :conversationId AND status != 'READ' AND isFromMe = 0")
    abstract suspend fun getUnreadMessageCount(conversationId: String): Int

    @Query("SELECT COUNT(*) FROM messages WHERE status != 'READ' AND isFromMe = 0")
    abstract fun getTotalUnreadMessageCount(): Flow<Int>

    @Query("SELECT * FROM messages WHERE content LIKE '%' || :query || '%' AND isDeleted = 0 ORDER BY timestamp DESC")
    abstract suspend fun searchMessages(query: String): List<Message>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun insertMessage(message: Message)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    abstract suspend fun insertMessages(messages: List<Message>)

    @Update
    abstract suspend fun updateMessage(message: Message)

    @Query("UPDATE messages SET status = :status WHERE id = :messageId")
    abstract suspend fun updateMessageStatus(messageId: String, status: MessageStatus)

    /// Look up the outbound row a `MessageAck` refers to. Returns
    /// `null` when no row carries this `wireId` — usually means the
    /// ack landed for a message we didn't send (e.g. the local user
    /// is a different group member, not the original sender).
    @Query("SELECT * FROM messages WHERE wireId = :wireId LIMIT 1")
    abstract suspend fun getMessageByWireId(wireId: String): Message?

    /**
     * Atomically read + update the row matched by `wireId` to record
     * `ackerIdHex` as a recipient that ack'd this message. Runs the
     * read and the write inside a single SQLite transaction so two
     * acks arriving simultaneously can't lose one to a last-write-
     * wins race against a stale read.
     *
     * Returns:
     *  * `Result.NotFound` — no row matches this `wireId`
     *    (`applyAck` returns false; caller logs at debug)
     *  * `Result.AlreadyApplied` — `ackerIdHex` was already in
     *    `deliveredAckers` (idempotent re-delivery)
     *  * `Result.Applied` — the row was updated; status moved to
     *    DELIVERED unless it was already READ
     *
     * Implemented as an open `@Transaction` method because Room's
     * code generator wraps it in `beginTransaction()` /
     * `endTransaction()` automatically — the abstract-class +
     * non-abstract-method pattern is the only way to compose
     * multiple DAO operations inside one transaction.
     */
    @Transaction
    open suspend fun applyAckTransactional(
        wireId: String,
        ackerIdHex: String,
    ): ApplyAckResult {
        val row = getMessageByWireId(wireId) ?: return ApplyAckResult.NotFound
        if (row.deliveredAckers.contains(ackerIdHex)) {
            return ApplyAckResult.AlreadyApplied
        }
        val updated = row.copy(
            deliveredAckers = row.deliveredAckers + ackerIdHex,
            status = if (row.status == MessageStatus.READ) {
                row.status
            } else {
                MessageStatus.DELIVERED
            },
        )
        updateMessage(updated)
        return ApplyAckResult.Applied
    }

    @Query("UPDATE messages SET status = 'READ' WHERE conversationId = :conversationId AND isFromMe = 0")
    abstract suspend fun markAllMessagesAsRead(conversationId: String)

    @Query("UPDATE messages SET isDeleted = 1, deletedAt = :deletedAt WHERE id = :messageId")
    abstract suspend fun markMessageAsDeleted(messageId: String, deletedAt: Long)

    @Query("DELETE FROM messages WHERE id = :messageId")
    abstract suspend fun deleteMessageById(messageId: String)

    @Query("DELETE FROM messages WHERE conversationId = :conversationId")
    abstract suspend fun deleteAllMessagesForConversation(conversationId: String)

    // Disappearing-message cleanup. Run periodically from
    // `MessageRepository.cleanupExpiredMessages` (called by
    // `MessageService`'s background loop).
    @Query("DELETE FROM messages WHERE disappearsAt IS NOT NULL AND disappearsAt < :nowSeconds")
    abstract suspend fun deleteExpiredMessages(nowSeconds: Long): Int

    @Query("SELECT COUNT(*) FROM messages WHERE conversationId = :conversationId")
    abstract suspend fun getMessageCountForConversation(conversationId: String): Int
}
