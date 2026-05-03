package com.qubee.messenger.data.repository

import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.data.model.ConversationWithDetails
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import kotlinx.coroutines.flow.Flow
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

// Real Room-backed implementation — rev-3 priority 6.
@Singleton
class ConversationRepository @Inject constructor(
    private val conversationDao: ConversationDao,
    @Suppress("unused") private val messageDao: MessageDao,
) {

    fun getAllConversations(): Flow<List<Conversation>> =
        conversationDao.getAllConversations()

    fun getConversationsWithDetails(): Flow<List<ConversationWithDetails>> =
        conversationDao.getConversationsWithDetails()

    fun getConversationFlow(conversationId: String): Flow<Conversation?> =
        conversationDao.getConversationFlow(conversationId)

    suspend fun getConversationById(conversationId: String): Conversation? =
        conversationDao.getConversationById(conversationId)

    /// Look up the existing direct conversation with `contactId` (if
    /// any) or mint a fresh `ConversationType.DIRECT` row and
    /// return its id. Used by `MessageService.onMessageReceived` to
    /// route inbound messages to a stable conversation.
    suspend fun getOrCreateConversationId(contactId: String): String {
        val existing = conversationDao.getConversationsByType(ConversationType.DIRECT)
            .firstOrNull { it.participants.contains(contactId) }
        if (existing != null) return existing.id

        val now = System.currentTimeMillis()
        val conversation = Conversation(
            id = UUID.randomUUID().toString(),
            type = ConversationType.DIRECT,
            name = "",
            participants = listOf(contactId),
            createdAt = now,
            updatedAt = now,
        )
        conversationDao.insertConversation(conversation)
        return conversation.id
    }

    suspend fun upsertConversation(conversation: Conversation) {
        conversationDao.insertConversation(conversation)
    }

    suspend fun updateArchivedStatus(conversationId: String, archived: Boolean) {
        conversationDao.updateArchivedStatus(conversationId, archived)
    }

    suspend fun updatePinnedStatus(conversationId: String, pinned: Boolean) {
        conversationDao.updatePinnedStatus(conversationId, pinned)
    }

    suspend fun deleteConversation(conversationId: String) {
        conversationDao.deleteConversationById(conversationId)
    }
}
