package com.qubee.messenger.data.repository.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageWithSender
import kotlinx.coroutines.flow.Flow

@Dao
interface MessageDao {

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId AND isDeleted = 0 ORDER BY timestamp ASC")
    fun getMessagesForConversation(conversationId: String): Flow<List<Message>>

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
    fun getMessagesWithSenderForConversation(conversationId: String): Flow<List<MessageWithSender>>

    @Query("SELECT * FROM messages WHERE id = :messageId")
    suspend fun getMessageById(messageId: String): Message?

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastMessageForConversation(conversationId: String): Message?

    @Query("SELECT COUNT(*) FROM messages WHERE conversationId = :conversationId AND status != 'READ' AND isFromMe = 0")
    suspend fun getUnreadMessageCount(conversationId: String): Int

    @Query("SELECT COUNT(*) FROM messages WHERE status != 'READ' AND isFromMe = 0")
    fun getTotalUnreadMessageCount(): Flow<Int>

    @Query("SELECT * FROM messages WHERE content LIKE '%' || :query || '%' AND isDeleted = 0 ORDER BY timestamp DESC")
    suspend fun searchMessages(query: String): List<Message>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: Message)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessages(messages: List<Message>)

    @Update
    suspend fun updateMessage(message: Message)

    @Query("UPDATE messages SET status = :status WHERE id = :messageId")
    suspend fun updateMessageStatus(messageId: String, status: MessageStatus)

    @Query("UPDATE messages SET status = 'READ' WHERE conversationId = :conversationId AND isFromMe = 0")
    suspend fun markAllMessagesAsRead(conversationId: String)

    @Query("UPDATE messages SET isDeleted = 1, deletedAt = :deletedAt WHERE id = :messageId")
    suspend fun markMessageAsDeleted(messageId: String, deletedAt: Long)

    @Query("DELETE FROM messages WHERE id = :messageId")
    suspend fun deleteMessageById(messageId: String)

    @Query("DELETE FROM messages WHERE conversationId = :conversationId")
    suspend fun deleteAllMessagesForConversation(conversationId: String)

    // Disappearing-message cleanup. Run periodically from
    // `MessageRepository.cleanupExpiredMessages` (called by
    // `MessageService`'s background loop).
    @Query("DELETE FROM messages WHERE disappearsAt IS NOT NULL AND disappearsAt < :nowSeconds")
    suspend fun deleteExpiredMessages(nowSeconds: Long): Int

    @Query("SELECT COUNT(*) FROM messages WHERE conversationId = :conversationId")
    suspend fun getMessageCountForConversation(conversationId: String): Int
}
