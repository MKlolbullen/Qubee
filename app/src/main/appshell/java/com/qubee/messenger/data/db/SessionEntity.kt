package com.qubee.messenger.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "sessions")
data class SessionEntity(
    @PrimaryKey val conversationId: String,
    val sessionId: String,
    val peerHandle: String,
    val keyMaterialBase64: String,
    val nativeBacked: Boolean,
    val state: String,
    val bootstrapPayloadBase64: String?,
    val algorithm: String,
    val createdAt: Long,
    val lastUsedAt: Long,
)
