package com.qubee.messenger.data.model

import androidx.room.ColumnInfo
import androidx.room.Embedded
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

// Room schema — rev-3 priority 1.
//
// The rev-2 stub revision of this file kept these as plain Kotlin
// data classes so the half-built ViewModels and Fragments compiled
// against a stable surface. Rev-3 turns them into real `@Entity`
// rows backed by Room (via `QubeeDatabase`) and SQLCipher
// (`SupportFactory`, see `data.repository.database.QubeeDatabase`).
//
// Schema gotchas:
//  * `Contact.metadata` (notes + tags) and the `Map<String,
//    List<String>>` reactions on `Message` go through Gson via
//    `Converters.kt`. `List<String>` for `Conversation.participants`
//    + `adminIds` likewise.
//  * Enums are stored as their `String` name (Room handles this via
//    converters in `Converters.kt`).
//  * `ByteArray?` is stored natively as `BLOB`.
//  * No foreign-key constraints today — the contact / conversation /
//    message lifecycle isn't symmetric (we receive messages from
//    not-yet-stored senders during the join handshake), so leaving
//    the columns un-FK'd avoids a class of insert-order races.
//    Indexes on the columns we'd otherwise FK keep the read path
//    cheap.

enum class TrustLevel {
    UNKNOWN,
    BASIC,
    ENHANCED,
    HIGH,
    MAXIMUM,
    TOFU,
    VERIFIED,
    /// A previously verified contact presented a different identity
    /// key. This is not automatically "compromised" — users can
    /// legitimately rotate/reset identities — but it must never be
    /// displayed as VERIFIED / PQ READY until the new identity is
    /// explicitly re-verified.
    KEY_CHANGED,
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

@Entity(
    tableName = "contacts",
    indices = [
        Index(value = ["identityId"], unique = true),
        // Indexed (not unique — `peerId` may be null for many
        // contacts before population code lights up). The lookup
        // path in `MessageService.onMessageReceived` is by peerId,
        // so the index keeps it cheap even at the 16-member group
        // cap times any number of casual contacts.
        Index(value = ["peerId"]),
    ],
)
data class Contact(
    @PrimaryKey val id: String = "",
    val identityId: String = "",
    val displayName: String = "",
    val phoneNumber: String? = null,
    val email: String? = null,
    val publicKey: ByteArray? = null,
    val identityKey: ByteArray? = null,
    /// libp2p PeerId string for routing inbound messages to the
    /// right contact. Nullable — set after the contact is paired
    /// via the invite/handshake flow OR observed inbound for the
    /// first time (TOFU). Null contacts won't match the
    /// `getContactByPeerId` lookup; the receive path falls back
    /// to using the libp2p sender id as the conversation key.
    val peerId: String? = null,
    val trustLevel: TrustLevel = TrustLevel.UNKNOWN,
    val verificationStatus: ContactVerificationStatus = ContactVerificationStatus.UNVERIFIED,
    val isBlocked: Boolean = false,
    val isOnline: Boolean = false,
    val lastSeen: Long? = null,
    val profilePictureUrl: String? = null,
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L,
    @Embedded(prefix = "metadata_") val metadata: ContactMetadata = ContactMetadata(),
)

data class ContactWithLastMessage(
    @Embedded val contact: Contact = Contact(),
    @ColumnInfo(name = "lastMessageContent") val lastMessageContent: String? = null,
    @ColumnInfo(name = "lastMessageTimestamp") val lastMessageTimestamp: Long? = null,
    @ColumnInfo(name = "unreadCount") val unreadCount: Int = 0,
)

// VIDEO + VOICE added in rev-3 to match the consumer in
// `ChatViewModel.toUiType()` which the parallel UI work introduced.
// They serialise to / from their `String` name via Converters.
enum class MessageType { TEXT, IMAGE, VIDEO, FILE, AUDIO, VOICE }

enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    READ,
    FAILED,
}

@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["conversationId"]),
        Index(value = ["senderId"]),
        Index(value = ["timestamp"]),
    ],
)
data class Message(
    @PrimaryKey val id: String = "",
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
    /// 32-char hex of the canonical group-message id (BLAKE3
    /// truncation; see `group_message_id` in
    /// `src/groups/group_message.rs`). Stamped at send time via
    /// `nativeExtractMessageId`. Inbound `onMessageAcked` looks up
    /// the row by this column to bump `deliveredAckers`. Null for
    /// rows that don't have a wire-level id yet (P2P direct
    /// path, pre-this-feature rows that survived migration).
    val wireId: String? = null,
    /// JSON-encoded list of acker `IdentityId` hex strings that
    /// have ack'd this outbound message. Empty until the first
    /// ack lands. Used for two things: deduping repeat acks from
    /// the same recipient (set semantics) and rendering the
    /// "delivered to N of M" hint on the chat row.
    val deliveredAckers: List<String> = emptyList(),
)

data class MessageWithSender(
    @Embedded val message: Message = Message(),
    @ColumnInfo(name = "senderName") val senderName: String = "",
)

enum class ConversationType { DIRECT, GROUP }

@Entity(
    tableName = "conversations",
    indices = [Index(value = ["lastMessageTimestamp"])],
)
data class Conversation(
    @PrimaryKey val id: String = "",
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
    @Embedded val conversation: Conversation = Conversation(),
    @Embedded(prefix = "lastMsg_") val lastMessage: Message? = null,
    @ColumnInfo(name = "unreadCount") val unreadCount: Int = 0,
)

enum class KeyType {
    IDENTITY,
    PRE_KEY,
    SESSION,
    GROUP,
}

@Entity(
    tableName = "crypto_keys",
    indices = [Index(value = ["contactId"])],
)
data class CryptoKey(
    @PrimaryKey val id: String = "",
    val contactId: String = "",
    val keyType: KeyType = KeyType.IDENTITY,
    val keyData: ByteArray = ByteArray(0),
    val createdAt: Long = 0L,
    val isActive: Boolean = true,
    val expiresAt: Long? = null,
)
