package com.qubee.messenger.data.db

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "guide_contacts")
data class GuideContactEntity(
    @PrimaryKey val contactId: String,
    val alias: String,
    val kyberPublicKey: ByteArray,
    val trustStatus: String,
    val lastSeen: Long,
)

@Entity(
    tableName = "guide_messages",
    foreignKeys = [
        ForeignKey(
            entity = GuideContactEntity::class,
            parentColumns = ["contactId"],
            childColumns = ["contactId"],
            onDelete = ForeignKey.CASCADE,
        )
    ],
    indices = [Index("contactId")],
)
data class GuideMessageEntity(
    @PrimaryKey val messageId: String,
    val contactId: String,
    val isSender: Boolean,
    val textContent: String,
    val timestamp: Long,
    val status: String,
)

@Entity(
    tableName = "guide_session_state",
    foreignKeys = [
        ForeignKey(
            entity = GuideContactEntity::class,
            parentColumns = ["contactId"],
            childColumns = ["contactId"],
            onDelete = ForeignKey.CASCADE,
        )
    ],
    indices = [Index("contactId")],
)
data class GuideSessionStateEntity(
    @PrimaryKey val sessionId: String,
    val contactId: String,
    val symmetricKey: ByteArray,
    val messageCount: Int,
)
