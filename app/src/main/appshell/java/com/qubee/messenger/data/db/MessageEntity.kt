package com.qubee.messenger.data.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "messages",
    indices = [Index(value = ["conversationId", "timestamp"])]
)
data class MessageEntity(
    @PrimaryKey val id: String,
    val conversationId: String,
    val sender: String,
    val body: String,
    val ciphertextBase64: String,
    val algorithm: String,
    val timestamp: Long,
    val deliveryState: String,
    val isEncrypted: Boolean,
    val originDeviceId: String? = null,
    val deliveredToDeviceCount: Int = 0,
    val deliveredToDevicesJson: String = "[]",
    val readByDeviceCount: Int = 0,
    val readByDevicesJson: String = "[]",
    val lastReceiptAt: Long = 0L,
)
