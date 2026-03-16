package com.qubee.messenger.data.database.dao

import androidx.room.*
import kotlinx.coroutines.flow.Flow
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationWithDetails
import com.qubee.messenger.data.model.ConversationType

@Dao
interface ConversationDao {

    @Query("SELECT * FROM conversations WHERE isArchived = 0 ORDER BY isPinned DESC, lastMessageTimestamp DESC")
    fun getAllConversations(): Flow<List<Conversation>>

    @Query("SELECT * FROM conversations WHERE isArchived = 1 ORDER BY lastMessageTimestamp DESC")
    fun getArchivedConversations(): Flow<List<Conversation>>

    @Query("SELECT * FROM conversations WHERE isPinned = 1 ORDER BY lastMessageTimestamp DESC")
    fun getPinnedConversations(): Flow<List<Conversation>>

    @Query("SELECT * FROM conversations WHERE id = :conversationId")
    suspend fun getConversationById(conversationId: String): Conversation?

    @Query("SELECT * FROM conversations WHERE type = :type")
    suspend fun getConversationsByType(type: ConversationType): List<Conversation>

    @Query("""
        SELECT c.*, 
               m.content as lastMessageContent,
               m.timestamp as lastMessageTimestamp,
               COUNT(CASE WHEN m.status != 3 AND m.isFromMe = 0 THEN 1 END) as unreadCount
        FROM conversations c
        LEFT JOIN (
            SELECT conversationId, content, timestamp, status, isFromMe,
                   ROW_NUMBER() OVER (PARTITION BY conversationId ORDER BY timestamp DESC) as rn
            FROM messages
        ) m ON c.id = m.conversationId AND m.rn = 1
        WHERE c.isArchived = 0
        GROUP BY c.id
        ORDER BY c.isPinned DESC, COALESCE(m.timestamp, c.createdAt) DESC
    """)
    fun getConversationsWithDetails(): Flow<List<ConversationWithDetails>>

    @Query("SELECT * FROM conversations WHERE participants LIKE '%' || :contactId || '%'")
    suspend fun getConversationsWithContact(contactId: String): List<Conversation>

    @Query("SELECT * FROM conversations WHERE type = 0 AND participants LIKE '%' || :contactId || '%'")
    suspend fun getDirectConversationWithContact(contactId: String): Conversation?

    @Query("SELECT * FROM conversations WHERE name LIKE '%' || :query || '%'")
    suspend fun searchConversations(query: String): List<Conversation>

    @Query("SELECT * FROM conversations WHERE isMuted = 1")
    suspend fun getMutedConversations(): List<Conversation>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertConversation(conversation: Conversation): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertConversations(conversations: List<Conversation>)

    @Update
    suspend fun updateConversation(conversation: Conversation)

    @Query("UPDATE conversations SET lastMessageId = :messageId, lastMessageTimestamp = :timestamp WHERE id = :conversationId")
    suspend fun updateLastMessage(conversationId: String, messageId: String, timestamp: Long)

    @Query("UPDATE conversations SET isArchived = :isArchived WHERE id = :conversationId")
    suspend fun updateArchivedStatus(conversationId: String, isArchived: Boolean)

    @Query("UPDATE conversations SET isPinned = :isPinned WHERE id = :conversationId")
    suspend fun updatePinnedStatus(conversationId: String, isPinned: Boolean)

    @Query("UPDATE conversations SET isMuted = :isMuted, muteUntil = :muteUntil WHERE id = :conversationId")
    suspend fun updateMuteStatus(conversationId: String, isMuted: Boolean, muteUntil: Long?)

    @Query("UPDATE conversations SET disappearingTimer = :timer WHERE id = :conversationId")
    suspend fun updateDisappearingTimer(conversationId: String, timer: Long)

    @Query("UPDATE conversations SET name = :name WHERE id = :conversationId")
    suspend fun updateConversationName(conversationId: String, name: String?)

    @Query("UPDATE conversations SET description = :description WHERE id = :conversationId")
    suspend fun updateConversationDescription(conversationId: String, description: String?)

    @Query("UPDATE conversations SET avatarUrl = :avatarUrl WHERE id = :conversationId")
    suspend fun updateConversationAvatar(conversationId: String, avatarUrl: String?)

    @Query("UPDATE conversations SET participants = :participants WHERE id = :conversationId")
    suspend fun updateParticipants(conversationId: String, participants: String)

    @Query("UPDATE conversations SET adminIds = :adminIds WHERE id = :conversationId")
    suspend fun updateAdminIds(conversationId: String, adminIds: String?)

    @Delete
    suspend fun deleteConversation(conversation: Conversation)

    @Query("DELETE FROM conversations WHERE id = :conversationId")
    suspend fun deleteConversationById(conversationId: String)

    @Query("DELETE FROM conversations WHERE isArchived = 1")
    suspend fun deleteAllArchivedConversations()

    @Query("SELECT COUNT(*) FROM conversations WHERE isArchived = 0")
    suspend fun getActiveConversationCount(): Int

    @Query("SELECT COUNT(*) FROM conversations WHERE isArchived = 1")
    suspend fun getArchivedConversationCount(): Int

    @Query("SELECT COUNT(*) FROM conversations WHERE type = :type")
    suspend fun getConversationCountByType(type: ConversationType): Int

    @Query("SELECT COUNT(*) FROM conversations WHERE isMuted = 1")
    suspend fun getMutedConversationCount(): Int
}

