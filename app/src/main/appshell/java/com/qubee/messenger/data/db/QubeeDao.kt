package com.qubee.messenger.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface QubeeDao {
    @Query("SELECT * FROM identity WHERE id = :id LIMIT 1")
    fun observeIdentity(id: String = IdentityEntity.SELF_ID): Flow<IdentityEntity?>

    @Query("SELECT * FROM identity WHERE id = :id LIMIT 1")
    suspend fun getIdentity(id: String = IdentityEntity.SELF_ID): IdentityEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertIdentity(identity: IdentityEntity)

    @Query("SELECT * FROM conversations ORDER BY updatedAt DESC")
    fun observeConversations(): Flow<List<ConversationEntity>>

    @Query("SELECT * FROM conversations WHERE id = :conversationId LIMIT 1")
    fun observeConversation(conversationId: String): Flow<ConversationEntity?>

    @Query("SELECT * FROM conversations WHERE id = :conversationId LIMIT 1")
    suspend fun getConversation(conversationId: String): ConversationEntity?

    @Query("SELECT * FROM conversations WHERE peerHandle = :peerHandle LIMIT 1")
    suspend fun getConversationByPeerHandle(peerHandle: String): ConversationEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertConversation(conversation: ConversationEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertConversations(conversations: List<ConversationEntity>)

    @Query("SELECT COUNT(*) FROM conversations")
    suspend fun conversationCount(): Int

    @Query("UPDATE conversations SET unreadCount = 0 WHERE id = :conversationId")
    suspend fun clearUnread(conversationId: String)

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp ASC")
    fun observeMessages(conversationId: String): Flow<List<MessageEntity>>

    @Query("SELECT * FROM messages WHERE id = :messageId LIMIT 1")
    suspend fun getMessage(messageId: String): MessageEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: MessageEntity)

    @Query("UPDATE messages SET deliveryState = :deliveryState WHERE id = :messageId")
    suspend fun updateMessageState(messageId: String, deliveryState: String)

    @Query("SELECT * FROM messages WHERE sender = :sender AND deliveryState IN (:states) ORDER BY timestamp ASC")
    suspend fun getMessagesBySenderAndStates(sender: String, states: List<String>): List<MessageEntity>

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId AND sender = :sender AND timestamp <= :timestamp ORDER BY timestamp ASC")
    suspend fun getMessagesUpToTimestamp(conversationId: String, sender: String, timestamp: Long): List<MessageEntity>

    @Query("SELECT COUNT(*) FROM messages WHERE conversationId = :conversationId AND sender = :sender AND deliveryState IN (:states)")
    fun observePendingOutboundCount(conversationId: String, sender: String, states: List<String>): Flow<Int>

    @Query("SELECT MAX(timestamp) FROM messages WHERE conversationId = :conversationId")
    fun observeLatestMessageTimestamp(conversationId: String): Flow<Long?>

    @Query("SELECT MAX(timestamp) FROM messages WHERE conversationId = :conversationId AND sender = :sender")
    suspend fun getLatestMessageTimestampBySender(conversationId: String, sender: String): Long?

    @Query("SELECT * FROM sessions WHERE conversationId = :conversationId LIMIT 1")
    suspend fun getSession(conversationId: String): SessionEntity?

    @Query("SELECT * FROM sessions WHERE conversationId = :conversationId LIMIT 1")
    fun observeSession(conversationId: String): Flow<SessionEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSession(session: SessionEntity)

    @Query("DELETE FROM sessions WHERE conversationId = :conversationId")
    suspend fun deleteSession(conversationId: String)

    @Query("SELECT * FROM sessions WHERE nativeBacked = 1")
    suspend fun getAllNativeSessions(): List<SessionEntity>

    @Query("SELECT * FROM sync_state WHERE id = :id LIMIT 1")
    suspend fun getSyncState(id: String = SyncStateEntity.RELAY_ID): SyncStateEntity?

    @Query("SELECT * FROM sync_state WHERE id = :id LIMIT 1")
    fun observeSyncState(id: String = SyncStateEntity.RELAY_ID): Flow<SyncStateEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertSyncState(syncState: SyncStateEntity)
}
