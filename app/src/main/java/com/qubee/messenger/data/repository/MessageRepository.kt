package com.qubee.messenger.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import com.qubee.messenger.data.database.dao.MessageDao
import com.qubee.messenger.data.database.dao.ConversationDao
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageWithSender
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.crypto.EncryptedMessage
import timber.log.Timber
import java.util.Date
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class MessageRepository @Inject constructor(
    private val messageDao: MessageDao,
    private val conversationDao: ConversationDao,
    private val qubeeManager: QubeeManager
) {

    fun getMessagesForConversation(conversationId: String): Flow<List<Message>> = 
        messageDao.getMessagesForConversation(conversationId)

    fun getMessagesWithSenderForConversation(conversationId: String): Flow<List<MessageWithSender>> = 
        messageDao.getMessagesWithSenderForConversation(conversationId)

    suspend fun getMessageById(messageId: String): Message? = messageDao.getMessageById(messageId)

    suspend fun getLastMessageForConversation(conversationId: String): Message? = 
        messageDao.getLastMessageForConversation(conversationId)

    suspend fun getUnreadMessagesForConversation(conversationId: String): List<Message> = 
        messageDao.getUnreadMessagesForConversation(conversationId)

    suspend fun getUnreadMessageCount(conversationId: String): Int = 
        messageDao.getUnreadMessageCount(conversationId)

    suspend fun getTotalUnreadMessageCount(): Int = messageDao.getTotalUnreadMessageCount()

    suspend fun searchMessages(query: String): List<Message> = messageDao.searchMessages(query)

    suspend fun sendTextMessage(
        conversationId: String,
        content: String,
        replyToMessageId: String? = null
    ): Result<Message> {
        return try {
            val message = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = getCurrentUserId(),
                content = content,
                contentType = MessageType.TEXT,
                timestamp = Date(),
                status = MessageStatus.SENDING,
                isFromMe = true,
                replyToMessageId = replyToMessageId
            )

            // Encrypt the message content
            val encryptedContent = encryptMessageContent(conversationId, content)
            val encryptedMessage = message.copy(content = encryptedContent)

            // Insert the message into the database
            messageDao.insertMessage(encryptedMessage)

            // Update conversation's last message
            updateConversationLastMessage(conversationId, encryptedMessage)

            // Set disappearing message timer if enabled
            setDisappearingMessageTimer(encryptedMessage)

            Timber.d("Sent text message in conversation $conversationId")
            Result.success(encryptedMessage)
        } catch (e: Exception) {
            Timber.e(e, "Failed to send text message in conversation $conversationId")
            Result.failure(e)
        }
    }

    suspend fun sendMediaMessage(
        conversationId: String,
        messageType: MessageType,
        filePath: String,
        mimeType: String,
        fileSize: Long,
        caption: String? = null
    ): Result<Message> {
        return try {
            val message = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = getCurrentUserId(),
                content = caption ?: "",
                contentType = messageType,
                timestamp = Date(),
                status = MessageStatus.SENDING,
                isFromMe = true,
                attachmentPath = filePath,
                attachmentMimeType = mimeType,
                attachmentSize = fileSize
            )

            // Encrypt the file if it's not already encrypted
            val encryptedFilePath = encryptFile(conversationId, filePath)
            val encryptedMessage = message.copy(attachmentPath = encryptedFilePath)

            // Insert the message into the database
            messageDao.insertMessage(encryptedMessage)

            // Update conversation's last message
            updateConversationLastMessage(conversationId, encryptedMessage)

            // Set disappearing message timer if enabled
            setDisappearingMessageTimer(encryptedMessage)

            Timber.d("Sent media message in conversation $conversationId")
            Result.success(encryptedMessage)
        } catch (e: Exception) {
            Timber.e(e, "Failed to send media message in conversation $conversationId")
            Result.failure(e)
        }
    }

    suspend fun receiveMessage(
        conversationId: String,
        senderId: String,
        encryptedContent: String,
        messageType: MessageType = MessageType.TEXT,
        timestamp: Date = Date(),
        attachmentData: ByteArray? = null
    ): Result<Message> {
        return try {
            // Decrypt the message content
            val decryptedContent = decryptMessageContent(conversationId, encryptedContent)

            val message = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = senderId,
                content = decryptedContent,
                contentType = messageType,
                timestamp = timestamp,
                status = MessageStatus.DELIVERED,
                isFromMe = false
            )

            // Handle attachment if present
            val finalMessage = if (attachmentData != null) {
                val decryptedFilePath = decryptAndSaveFile(conversationId, attachmentData)
                message.copy(attachmentPath = decryptedFilePath)
            } else {
                message
            }

            // Insert the message into the database
            messageDao.insertMessage(finalMessage)

            // Update conversation's last message
            updateConversationLastMessage(conversationId, finalMessage)

            // Set disappearing message timer if enabled
            setDisappearingMessageTimer(finalMessage)

            Timber.d("Received message in conversation $conversationId from $senderId")
            Result.success(finalMessage)
        } catch (e: Exception) {
            Timber.e(e, "Failed to receive message in conversation $conversationId")
            Result.failure(e)
        }
    }

    suspend fun markMessageAsRead(messageId: String): Result<Unit> {
        return try {
            messageDao.updateMessageStatus(messageId, MessageStatus.READ)
            Timber.d("Marked message as read: $messageId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to mark message as read: $messageId")
            Result.failure(e)
        }
    }

    suspend fun markAllMessagesAsRead(conversationId: String): Result<Unit> {
        return try {
            messageDao.markAllMessagesAsRead(conversationId)
            Timber.d("Marked all messages as read in conversation: $conversationId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to mark all messages as read in conversation: $conversationId")
            Result.failure(e)
        }
    }

    suspend fun editMessage(messageId: String, newContent: String): Result<Unit> {
        return try {
            val message = messageDao.getMessageById(messageId)
                ?: return Result.failure(Exception("Message not found"))

            if (!message.isFromMe) {
                return Result.failure(Exception("Cannot edit messages from other users"))
            }

            // Encrypt the new content
            val encryptedContent = encryptMessageContent(message.conversationId, newContent)
            messageDao.editMessage(messageId, encryptedContent, Date())

            Timber.d("Edited message: $messageId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to edit message: $messageId")
            Result.failure(e)
        }
    }

    suspend fun deleteMessage(messageId: String, deleteForEveryone: Boolean = false): Result<Unit> {
        return try {
            if (deleteForEveryone) {
                // Mark as deleted but keep in database for sync purposes
                messageDao.markMessageAsDeleted(messageId, Date())
            } else {
                // Delete locally only
                messageDao.deleteMessageById(messageId)
            }

            Timber.d("Deleted message: $messageId (deleteForEveryone: $deleteForEveryone)")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to delete message: $messageId")
            Result.failure(e)
        }
    }

    suspend fun addReactionToMessage(messageId: String, emoji: String): Result<Unit> {
        return try {
            val message = messageDao.getMessageById(messageId)
                ?: return Result.failure(Exception("Message not found"))

            // Parse existing reactions
            val reactions = parseReactions(message.reactions)
            val userId = getCurrentUserId()

            // Add or update reaction
            val updatedReactions = reactions.toMutableMap()
            updatedReactions[userId] = emoji

            // Save updated reactions
            val reactionsJson = serializeReactions(updatedReactions)
            messageDao.updateMessageReactions(messageId, reactionsJson)

            Timber.d("Added reaction to message: $messageId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to add reaction to message: $messageId")
            Result.failure(e)
        }
    }

    suspend fun removeReactionFromMessage(messageId: String): Result<Unit> {
        return try {
            val message = messageDao.getMessageById(messageId)
                ?: return Result.failure(Exception("Message not found"))

            // Parse existing reactions
            val reactions = parseReactions(message.reactions)
            val userId = getCurrentUserId()

            // Remove reaction
            val updatedReactions = reactions.toMutableMap()
            updatedReactions.remove(userId)

            // Save updated reactions
            val reactionsJson = if (updatedReactions.isEmpty()) null else serializeReactions(updatedReactions)
            messageDao.updateMessageReactions(messageId, reactionsJson)

            Timber.d("Removed reaction from message: $messageId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to remove reaction from message: $messageId")
            Result.failure(e)
        }
    }

    suspend fun cleanupExpiredMessages(): Result<Int> {
        return try {
            val currentTime = System.currentTimeMillis()
            val deletedCount = messageDao.deleteExpiredMessages(currentTime)
            Timber.d("Cleaned up $deletedCount expired messages")
            Result.success(deletedCount)
        } catch (e: Exception) {
            Timber.e(e, "Failed to cleanup expired messages")
            Result.failure(e)
        }
    }

    suspend fun getMessageCountForConversation(conversationId: String): Int = 
        messageDao.getMessageCountForConversation(conversationId)

    suspend fun getMessagesWithAttachments(): List<Message> = messageDao.getMessagesWithAttachments()

    suspend fun getTotalAttachmentSize(): Long = messageDao.getTotalAttachmentSize() ?: 0L

    private suspend fun encryptMessageContent(conversationId: String, content: String): String {
        return try {
            val encryptedMessage = qubeeManager.encryptMessage(conversationId, content)
            if (encryptedMessage != null) {
                // Convert encrypted message to base64 string for storage
                android.util.Base64.encodeToString(
                    encryptedMessage.toBytes(),
                    android.util.Base64.DEFAULT
                )
            } else {
                throw Exception("Failed to encrypt message")
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to encrypt message content")
            throw e
        }
    }

    private suspend fun decryptMessageContent(conversationId: String, encryptedContent: String): String {
        return try {
            val encryptedBytes = android.util.Base64.decode(encryptedContent, android.util.Base64.DEFAULT)
            val encryptedMessage = EncryptedMessage.fromBytes(encryptedBytes)
                ?: throw Exception("Failed to parse encrypted message")

            qubeeManager.decryptMessage(conversationId, encryptedMessage)
                ?: throw Exception("Failed to decrypt message")
        } catch (e: Exception) {
            Timber.e(e, "Failed to decrypt message content")
            throw e
        }
    }

    private suspend fun encryptFile(conversationId: String, filePath: String): String {
        return try {
            // Read file data
            val fileData = java.io.File(filePath).readBytes()
            
            // Encrypt file
            val encryptedFile = qubeeManager.encryptFile(conversationId, fileData)
                ?: throw Exception("Failed to encrypt file")

            // Save encrypted file
            val encryptedFilePath = "${filePath}.encrypted"
            java.io.File(encryptedFilePath).writeBytes(encryptedFile.toBytes())
            
            encryptedFilePath
        } catch (e: Exception) {
            Timber.e(e, "Failed to encrypt file: $filePath")
            throw e
        }
    }

    private suspend fun decryptAndSaveFile(conversationId: String, encryptedData: ByteArray): String {
        return try {
            // Parse encrypted file
            val encryptedFile = com.qubee.messenger.crypto.EncryptedFile.fromBytes(encryptedData)
                ?: throw Exception("Failed to parse encrypted file")

            // Decrypt file
            val decryptedData = qubeeManager.decryptFile(conversationId, encryptedFile)
                ?: throw Exception("Failed to decrypt file")

            // Save decrypted file
            val decryptedFilePath = "/data/data/com.qubee.messenger/files/decrypted_${System.currentTimeMillis()}"
            java.io.File(decryptedFilePath).writeBytes(decryptedData)
            
            decryptedFilePath
        } catch (e: Exception) {
            Timber.e(e, "Failed to decrypt and save file")
            throw e
        }
    }

    private suspend fun updateConversationLastMessage(conversationId: String, message: Message) {
        try {
            conversationDao.updateLastMessage(conversationId, message.id, message.timestamp.time)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update conversation last message")
        }
    }

    private suspend fun setDisappearingMessageTimer(message: Message) {
        try {
            val conversation = conversationDao.getConversationById(message.conversationId)
            if (conversation?.disappearingTimer != null && conversation.disappearingTimer > 0) {
                val disappearsAt = Date(message.timestamp.time + (conversation.disappearingTimer * 1000))
                val updatedMessage = message.copy(disappearsAt = disappearsAt)
                messageDao.updateMessage(updatedMessage)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to set disappearing message timer")
        }
    }

    private fun parseReactions(reactionsJson: String?): Map<String, String> {
        return try {
            if (reactionsJson.isNullOrEmpty()) {
                emptyMap()
            } else {
                com.google.gson.Gson().fromJson(
                    reactionsJson,
                    object : com.google.gson.reflect.TypeToken<Map<String, String>>() {}.type
                ) ?: emptyMap()
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to parse reactions")
            emptyMap()
        }
    }

    private fun serializeReactions(reactions: Map<String, String>): String {
        return com.google.gson.Gson().toJson(reactions)
    }

    private fun getCurrentUserId(): String {
        // This should return the current user's ID
        // For now, return a placeholder - this would be implemented based on user management
        return "current_user_id"
    }
}

