package com.qubee.messenger.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey val id: String,
    val title: String,
    val subtitle: String,
    val peerHandle: String,
    val peerBundleBase64: String,
    val lastMessagePreview: String,
    val unreadCount: Int,
    val isVerified: Boolean,
    val updatedAt: Long,
    val lastContactRequestId: String? = null,
    val trustResetRequired: Boolean = false,
    val previousPeerFingerprint: String? = null,
    val lastKeyChangeAt: Long = 0L,
    val lastReadCursorAt: Long = 0L,
)
