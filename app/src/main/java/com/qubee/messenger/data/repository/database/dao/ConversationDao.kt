package com.qubee.messenger.data.repository.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.data.model.ConversationWithDetails
import kotlinx.coroutines.flow.Flow

@Dao
interface ConversationDao {

    @Query("SELECT * FROM conversations WHERE isArchived = 0 ORDER BY lastMessageTimestamp DESC, updatedAt DESC")
    fun getAllConversations(): Flow<List<Conversation>>

    @Query("SELECT * FROM conversations WHERE isArchived = 1 ORDER BY updatedAt DESC")
    fun getArchivedConversations(): Flow<List<Conversation>>

    @Query("SELECT * FROM conversations WHERE isPinned = 1 ORDER BY lastMessageTimestamp DESC")
    fun getPinnedConversations(): Flow<List<Conversation>>

    // Conversations + their last message + unread count for the
    // home / inbox surface. The last-message join uses a window
    // function so we get the actual most-recent row, not just any.
    @Query(
        """
        SELECT c.*,
               m.id as lastMsg_id,
               m.conversationId as lastMsg_conversationId,
               m.senderId as lastMsg_senderId,
               m.content as lastMsg_content,
               m.contentType as lastMsg_contentType,
               m.timestamp as lastMsg_timestamp,
               m.status as lastMsg_status,
               m.isFromMe as lastMsg_isFromMe,
               m.replyToMessageId as lastMsg_replyToMessageId,
               m.attachmentPath as lastMsg_attachmentPath,
               m.attachmentMimeType as lastMsg_attachmentMimeType,
               m.attachmentSize as lastMsg_attachmentSize,
               m.reactions as lastMsg_reactions,
               m.isDeleted as lastMsg_isDeleted,
               m.deletedAt as lastMsg_deletedAt,
               m.editedAt as lastMsg_editedAt,
               m.disappearsAt as lastMsg_disappearsAt,
               (SELECT COUNT(*) FROM messages
                WHERE conversationId = c.id
                  AND status != 'READ'
                  AND isFromMe = 0) as unreadCount
        FROM conversations c
        LEFT JOIN (
            SELECT *,
                   ROW_NUMBER() OVER (PARTITION BY conversationId ORDER BY timestamp DESC) as rn
            FROM messages
            WHERE isDeleted = 0
        ) m ON c.id = m.conversationId AND m.rn = 1
        WHERE c.isArchived = 0
        ORDER BY COALESCE(m.timestamp, c.updatedAt) DESC
        """
    )
    fun getConversationsWithDetails(): Flow<List<ConversationWithDetails>>

    @Query("SELECT * FROM conversations WHERE id = :conversationId")
    suspend fun getConversationById(conversationId: String): Conversation?

    @Query("SELECT * FROM conversations WHERE id = :conversationId")
    fun getConversationFlow(conversationId: String): Flow<Conversation?>

    @Query("SELECT * FROM conversations WHERE type = :type")
    suspend fun getConversationsByType(type: ConversationType): List<Conversation>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertConversation(conversation: Conversation)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertConversations(conversations: List<Conversation>)

    @Update
    suspend fun updateConversation(conversation: Conversation)

    @Query("UPDATE conversations SET lastMessageId = :messageId, lastMessageTimestamp = :timestamp WHERE id = :conversationId")
    suspend fun updateLastMessage(conversationId: String, messageId: String?, timestamp: Long?)

    @Query("UPDATE conversations SET isArchived = :isArchived WHERE id = :conversationId")
    suspend fun updateArchivedStatus(conversationId: String, isArchived: Boolean)

    @Query("UPDATE conversations SET isPinned = :isPinned WHERE id = :conversationId")
    suspend fun updatePinnedStatus(conversationId: String, isPinned: Boolean)

    @Query("DELETE FROM conversations WHERE id = :conversationId")
    suspend fun deleteConversationById(conversationId: String)
}
