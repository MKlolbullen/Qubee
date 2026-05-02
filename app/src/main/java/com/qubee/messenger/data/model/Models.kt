package com.qubee.messenger.data.model

// Pre-alpha placeholder data layer. The Android app's chat / contacts /
// conversation persistence has not been built yet (see the pre-alpha
// plan A4). These types exist so the half-built ViewModels, Fragments,
// Repositories, and DAOs that reference them compile. Anything that
// reaches a method on a Repository today gets an empty / no-op response.

enum class TrustLevel {
    UNKNOWN,
    BASIC,
    ENHANCED,
    HIGH,
    MAXIMUM,
    TOFU,
    VERIFIED,
    COMPROMISED,
}

enum class ContactVerificationStatus {
    UNVERIFIED,
    VERIFIED_ONCE,
    VERIFIED_MULTIPLE,
}

data class ContactMetadata(
    val notes: String = "",
    val tags: List<String> = emptyList(),
)

data class Contact(
    val id: String = "",
    val identityId: String = "",
    val displayName: String = "",
    val phoneNumber: String? = null,
    val email: String? = null,
    val publicKey: ByteArray? = null,
    val identityKey: ByteArray? = null,
    val trustLevel: TrustLevel = TrustLevel.UNKNOWN,
    val verificationStatus: ContactVerificationStatus = ContactVerificationStatus.UNVERIFIED,
    val isBlocked: Boolean = false,
    val isOnline: Boolean = false,
    val lastSeen: Long? = null,
    val profilePictureUrl: String? = null,
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L,
    val metadata: ContactMetadata = ContactMetadata(),
)

data class ContactWithLastMessage(
    val contact: Contact = Contact(),
    val lastMessageContent: String? = null,
    val lastMessageTimestamp: Long? = null,
    val unreadCount: Int = 0,
)

enum class MessageType { TEXT, IMAGE, FILE, AUDIO }

enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    READ,
    FAILED,
}

data class Message(
    val id: String = "",
    val conversationId: String = "",
    val senderId: String = "",
    val content: String = "",
    val contentType: MessageType = MessageType.TEXT,
    val timestamp: Long = 0L,
    val status: MessageStatus = MessageStatus.SENDING,
    val isFromMe: Boolean = false,
    val replyToMessageId: String? = null,
    val attachmentPath: String? = null,
    val attachmentMimeType: String? = null,
    val attachmentSize: Long? = null,
    val reactions: Map<String, List<String>> = emptyMap(),
    val isDeleted: Boolean = false,
    val deletedAt: Long? = null,
    val editedAt: Long? = null,
    val disappearsAt: Long? = null,
)

data class MessageWithSender(
    val message: Message = Message(),
    val senderName: String = "",
)

enum class ConversationType { DIRECT, GROUP }

data class Conversation(
    val id: String = "",
    val type: ConversationType = ConversationType.DIRECT,
    val name: String = "",
    val description: String? = null,
    val participants: List<String> = emptyList(),
    val adminIds: List<String> = emptyList(),
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L,
    val isArchived: Boolean = false,
    val isPinned: Boolean = false,
    val isMuted: Boolean = false,
    val muteUntil: Long? = null,
    val disappearingTimer: Long? = null,
    val lastMessageId: String? = null,
    val lastMessageTimestamp: Long? = null,
    val avatarUrl: String? = null,
)

data class ConversationWithDetails(
    val conversation: Conversation = Conversation(),
    val lastMessage: Message? = null,
    val unreadCount: Int = 0,
)

enum class KeyType {
    IDENTITY,
    PRE_KEY,
    SESSION,
    GROUP,
}

data class CryptoKey(
    val id: String = "",
    val contactId: String = "",
    val keyType: KeyType = KeyType.IDENTITY,
    val keyData: ByteArray = ByteArray(0),
    val createdAt: Long = 0L,
    val isActive: Boolean = true,
    val expiresAt: Long? = null,
)
