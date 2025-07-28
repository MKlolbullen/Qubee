package com.qubee.messenger.data.repository

import kotlinx.coroutines.flow.Flow
import com.qubee.messenger.data.database.dao.ConversationDao
import com.qubee.messenger.data.database.dao.MessageDao
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationWithDetails
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.crypto.QubeeManager
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import timber.log.Timber
import java.util.Date
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConversationRepository @Inject constructor(
    private val conversationDao: ConversationDao,
    private val messageDao: MessageDao,
    private val qubeeManager: QubeeManager,
    private val gson: Gson = Gson()
) {

    fun getAllConversations(): Flow<List<Conversation>> = conversationDao.getAllConversations()

    fun getArchivedConversations(): Flow<List<Conversation>> = conversationDao.getArchivedConversations()

    fun getPinnedConversations(): Flow<List<Conversation>> = conversationDao.getPinnedConversations()

    fun getConversationsWithDetails(): Flow<List<ConversationWithDetails>> = 
        conversationDao.getConversationsWithDetails()

    suspend fun getConversationById(conversationId: String): Conversation? = 
        conversationDao.getConversationById(conversationId)

    suspend fun getConversationsByType(type: ConversationType): List<Conversation> = 
        conversationDao.getConversationsByType(type)

    suspend fun getDirectConversationWithContact(contactId: String): Conversation? = 
        conversationDao.getDirectConversationWithContact(contactId)

    suspend fun searchConversations(query: String): List<Conversation> = 
        conversationDao.searchConversations(query)

    suspend fun createDirectConversation(contactId: String): Result<Conversation> {
        return try {
            // Check if conversation already exists
            val existingConversation = conversationDao.getDirectConversationWithContact(contactId)
            if (existingConversation != null) {
                return Result.success(existingConversation)
            }

            val participants = listOf(getCurrentUserId(), contactId)
            val conversation = Conversation(
                id = UUID.randomUUID().toString(),
                type = ConversationType.DIRECT,
                participants = gson.toJson(participants),
                createdAt = Date(),
                updatedAt = Date()
            )

            conversationDao.insertConversation(conversation)
            
            // Create ratchet session for this conversation
            createRatchetSession(conversation.id, contactId)
            
            Timber.d("Created direct conversation with contact $contactId")
            Result.success(conversation)
        } catch (e: Exception) {
            Timber.e(e, "Failed to create direct conversation with contact $contactId")
            Result.failure(e)
        }
    }

    suspend fun createGroupConversation(
        name: String,
        description: String? = null,
        participantIds: List<String>
    ): Result<Conversation> {
        return try {
            val allParticipants = (participantIds + getCurrentUserId()).distinct()
            val conversation = Conversation(
                id = UUID.randomUUID().toString(),
                type = ConversationType.GROUP,
                name = name,
                description = description,
                participants = gson.toJson(allParticipants),
                adminIds = gson.toJson(listOf(getCurrentUserId())),
                createdAt = Date(),
                updatedAt = Date()
            )

            conversationDao.insertConversation(conversation)
            
            // Create ratchet sessions for all participants
            participantIds.forEach { participantId ->
                createRatchetSession(conversation.id, participantId)
            }
            
            Timber.d("Created group conversation: $name with ${participantIds.size} participants")
            Result.success(conversation)
        } catch (e: Exception) {
            Timber.e(e, "Failed to create group conversation: $name")
            Result.failure(e)
        }
    }

    suspend fun updateConversationName(conversationId: String, name: String): Result<Unit> {
        return try {
            conversationDao.updateConversationName(conversationId, name)
            Timber.d("Updated conversation name: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update conversation name: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun updateConversationDescription(conversationId: String, description: String?): Result<Unit> {
        return try {
            conversationDao.updateConversationDescription(conversationId, description)
            Timber.d("Updated conversation description: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update conversation description: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun addParticipantToGroup(conversationId: String, participantId: String): Result<Unit> {
        return try {
            val conversation = conversationDao.getConversationById(conversationId)
                ?: return Result.failure(Exception("Conversation not found"))

            if (conversation.type != ConversationType.GROUP) {
                return Result.failure(Exception("Cannot add participants to non-group conversation"))
            }

            val currentParticipants = getParticipantIds(conversation.participants)
            if (participantId in currentParticipants) {
                return Result.failure(Exception("Participant already in group"))
            }

            val updatedParticipants = currentParticipants + participantId
            conversationDao.updateParticipants(conversationId, gson.toJson(updatedParticipants))
            
            // Create ratchet session for new participant
            createRatchetSession(conversationId, participantId)
            
            Timber.d("Added participant $participantId to group $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to add participant to group: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun removeParticipantFromGroup(conversationId: String, participantId: String): Result<Unit> {
        return try {
            val conversation = conversationDao.getConversationById(conversationId)
                ?: return Result.failure(Exception("Conversation not found"))

            if (conversation.type != ConversationType.GROUP) {
                return Result.failure(Exception("Cannot remove participants from non-group conversation"))
            }

            val currentParticipants = getParticipantIds(conversation.participants)
            if (participantId !in currentParticipants) {
                return Result.failure(Exception("Participant not in group"))
            }

            val updatedParticipants = currentParticipants - participantId
            conversationDao.updateParticipants(conversationId, gson.toJson(updatedParticipants))
            
            Timber.d("Removed participant $participantId from group $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to remove participant from group: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun archiveConversation(conversationId: String): Result<Unit> {
        return try {
            conversationDao.updateArchivedStatus(conversationId, true)
            Timber.d("Archived conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to archive conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun unarchiveConversation(conversationId: String): Result<Unit> {
        return try {
            conversationDao.updateArchivedStatus(conversationId, false)
            Timber.d("Unarchived conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to unarchive conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun pinConversation(conversationId: String): Result<Unit> {
        return try {
            conversationDao.updatePinnedStatus(conversationId, true)
            Timber.d("Pinned conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to pin conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun unpinConversation(conversationId: String): Result<Unit> {
        return try {
            conversationDao.updatePinnedStatus(conversationId, false)
            Timber.d("Unpinned conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to unpin conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun muteConversation(conversationId: String, muteUntil: Date? = null): Result<Unit> {
        return try {
            conversationDao.updateMuteStatus(conversationId, true, muteUntil?.time)
            Timber.d("Muted conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to mute conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun unmuteConversation(conversationId: String): Result<Unit> {
        return try {
            conversationDao.updateMuteStatus(conversationId, false, null)
            Timber.d("Unmuted conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to unmute conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun setDisappearingMessageTimer(conversationId: String, timerSeconds: Long): Result<Unit> {
        return try {
            conversationDao.updateDisappearingTimer(conversationId, timerSeconds)
            Timber.d("Set disappearing message timer for $conversationId: ${timerSeconds}s")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to set disappearing message timer: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun updateLastMessage(conversationId: String, messageId: String, timestamp: Date): Result<Unit> {
        return try {
            conversationDao.updateLastMessage(conversationId, messageId, timestamp.time)
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update last message for conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun deleteConversation(conversationId: String): Result<Unit> {
        return try {
            // Delete all messages in the conversation
            messageDao.deleteAllMessagesForConversation(conversationId)
            
            // Delete the conversation
            conversationDao.deleteConversationById(conversationId)
            
            Timber.d("Deleted conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to delete conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun getActiveConversationCount(): Int = conversationDao.getActiveConversationCount()

    suspend fun getArchivedConversationCount(): Int = conversationDao.getArchivedConversationCount()

    suspend fun getConversationCountByType(type: ConversationType): Int = 
        conversationDao.getConversationCountByType(type)

    private suspend fun createRatchetSession(conversationId: String, contactId: String) {
        try {
            // This would create a ratchet session with the contact
            // For now, we'll just log it - the actual implementation would depend on
            // how we handle key exchange and session establishment
            Timber.d("Creating ratchet session for conversation $conversationId with contact $contactId")
        } catch (e: Exception) {
            Timber.e(e, "Failed to create ratchet session for $conversationId with $contactId")
        }
    }

    private fun getParticipantIds(participantsJson: String): List<String> {
        return try {
            val type = object : TypeToken<List<String>>() {}.type
            gson.fromJson(participantsJson, type) ?: emptyList()
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse participant IDs")
            emptyList()
        }
    }

    private fun getCurrentUserId(): String {
        // This should return the current user's ID
        // For now, return a placeholder - this would be implemented based on user management
        return "current_user_id"
    }
}

