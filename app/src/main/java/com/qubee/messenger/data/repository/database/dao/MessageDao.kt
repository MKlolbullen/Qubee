package com.qubee.messenger.data.database.dao

import androidx.room.*
import kotlinx.coroutines.flow.Flow
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageWithSender
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.model.MessageStatus
import java.util.Date

@Dao
interface MessageDao {

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp ASC")
    fun getMessagesForConversation(conversationId: String): Flow<List<Message>>

    @Query("""
        SELECT m.*, c.displayName as senderName, c.profilePictureUrl as senderAvatar
        FROM messages m
        LEFT JOIN contacts c ON m.senderId = c.id
        WHERE m.conversationId = :conversationId
        ORDER BY m.timestamp ASC
    """)
    fun getMessagesWithSenderForConversation(conversationId: String): Flow<List<MessageWithSender>>

    @Query("SELECT * FROM messages WHERE id = :messageId")
    suspend fun getMessageById(messageId: String): Message?

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastMessageForConversation(conversationId: String): Message?

    @Query("""
        SELECT * FROM messages 
        WHERE conversationId = :conversationId 
        AND timestamp < :beforeTimestamp 
        ORDER BY timestamp DESC 
        LIMIT :limit
    """)
    suspend fun getMessagesBefore(conversationId: String, beforeTimestamp: Long, limit: Int): List<Message>

    @Query("""
        SELECT * FROM messages 
        WHERE conversationId = :conversationId 
        AND timestamp > :afterTimestamp 
        ORDER BY timestamp ASC 
        LIMIT :limit
    """)
    suspend fun getMessagesAfter(conversationId: String, afterTimestamp: Long, limit: Int): List<Message>

    @Query("SELECT * FROM messages WHERE contentType = :messageType ORDER BY timestamp DESC")
    suspend fun getMessagesByType(messageType: MessageType): List<Message>

    @Query("SELECT * FROM messages WHERE status = :status")
    suspend fun getMessagesByStatus(status: MessageStatus): List<Message>

    @Query("SELECT * FROM messages WHERE isFromMe = 0 AND status != 3 AND conversationId = :conversationId")
    suspend fun getUnreadMessagesForConversation(conversationId: String): List<Message>

    @Query("SELECT COUNT(*) FROM messages WHERE isFromMe = 0 AND status != 3 AND conversationId = :conversationId")
    suspend fun getUnreadMessageCount(conversationId: String): Int

    @Query("SELECT COUNT(*) FROM messages WHERE isFromMe = 0 AND status != 3")
    suspend fun getTotalUnreadMessageCount(): Int

    @Query("SELECT * FROM messages WHERE content LIKE '%' || :query || '%' ORDER BY timestamp DESC")
    suspend fun searchMessages(query: String): List<Message>

    @Query("SELECT * FROM messages WHERE disappearsAt IS NOT NULL AND disappearsAt <= :currentTime")
    suspend fun getExpiredMessages(currentTime: Long): List<Message>

    @Query("SELECT * FROM messages WHERE isDeleted = 1")
    suspend fun getDeletedMessages(): List<Message>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: Message): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessages(messages: List<Message>)

    @Update
    suspend fun updateMessage(message: Message)

    @Query("UPDATE messages SET status = :status WHERE id = :messageId")
    suspend fun updateMessageStatus(messageId: String, status: MessageStatus)

    @Query("UPDATE messages SET status = :status WHERE conversationId = :conversationId AND isFromMe = 0 AND status != 3")
    suspend fun markAllMessagesAsRead(conversationId: String, status: MessageStatus = MessageStatus.READ)

    @Query("UPDATE messages SET content = :newContent, editedAt = :editedAt WHERE id = :messageId")
    suspend fun editMessage(messageId: String, newContent: String, editedAt: Date)

    @Query("UPDATE messages SET isDeleted = 1, deletedAt = :deletedAt WHERE id = :messageId")
    suspend fun markMessageAsDeleted(messageId: String, deletedAt: Date)

    @Query("UPDATE messages SET reactions = :reactions WHERE id = :messageId")
    suspend fun updateMessageReactions(messageId: String, reactions: String?)

    @Delete
    suspend fun deleteMessage(message: Message)

    @Query("DELETE FROM messages WHERE id = :messageId")
    suspend fun deleteMessageById(messageId: String)

    @Query("DELETE FROM messages WHERE conversationId = :conversationId")
    suspend fun deleteAllMessagesForConversation(conversationId: String)

    @Query("DELETE FROM messages WHERE disappearsAt IS NOT NULL AND disappearsAt <= :currentTime")
    suspend fun deleteExpiredMessages(currentTime: Long): Int

    @Query("DELETE FROM messages WHERE isDeleted = 1 AND deletedAt <= :beforeTime")
    suspend fun deleteOldDeletedMessages(beforeTime: Long): Int

    @Query("SELECT COUNT(*) FROM messages WHERE conversationId = :conversationId")
    suspend fun getMessageCountForConversation(conversationId: String): Int

    @Query("SELECT COUNT(*) FROM messages WHERE contentType = :messageType")
    suspend fun getMessageCountByType(messageType: MessageType): Int

    @Query("SELECT * FROM messages WHERE attachmentPath IS NOT NULL ORDER BY timestamp DESC")
    suspend fun getMessagesWithAttachments(): List<Message>

    @Query("SELECT SUM(attachmentSize) FROM messages WHERE attachmentPath IS NOT NULL")
    suspend fun getTotalAttachmentSize(): Long?
}

