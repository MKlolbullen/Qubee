package com.qubee.messenger.data.database

import androidx.room.TypeConverter
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.ConversationType
import java.util.Date

class Converters {

    @TypeConverter
    fun fromTimestamp(value: Long?): Date? {
        return value?.let { Date(it) }
    }

    @TypeConverter
    fun dateToTimestamp(date: Date?): Long? {
        return date?.time
    }

    @TypeConverter
    fun fromByteArray(value: ByteArray?): String? {
        return value?.let { android.util.Base64.encodeToString(it, android.util.Base64.DEFAULT) }
    }

    @TypeConverter
    fun toByteArray(value: String?): ByteArray? {
        return value?.let { android.util.Base64.decode(it, android.util.Base64.DEFAULT) }
    }

    @TypeConverter
    fun fromTrustLevel(value: TrustLevel): Int {
        return value.value
    }

    @TypeConverter
    fun toTrustLevel(value: Int): TrustLevel {
        return TrustLevel.values().find { it.value == value } ?: TrustLevel.UNKNOWN
    }

    @TypeConverter
    fun fromMessageType(value: MessageType): Int {
        return value.value
    }

    @TypeConverter
    fun toMessageType(value: Int): MessageType {
        return MessageType.values().find { it.value == value } ?: MessageType.TEXT
    }

    @TypeConverter
    fun fromMessageStatus(value: MessageStatus): Int {
        return value.value
    }

    @TypeConverter
    fun toMessageStatus(value: Int): MessageStatus {
        return MessageStatus.values().find { it.value == value } ?: MessageStatus.SENDING
    }

    @TypeConverter
    fun fromConversationType(value: ConversationType): Int {
        return value.value
    }

    @TypeConverter
    fun toConversationType(value: Int): ConversationType {
        return ConversationType.values().find { it.value == value } ?: ConversationType.DIRECT
    }
}

