package com.qubee.messenger.data.repository.database

import androidx.room.TypeConverter
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.data.model.KeyType
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.model.TrustLevel

// Room TypeConverters for the `data.model` types Room can't store
// natively. Enums round-trip as their `String` name; collections
// round-trip as Gson JSON strings (Gson is already a project dep,
// see app/build.gradle:142). `ByteArray?` is handled natively by
// Room and doesn't need a converter.
//
// Why JSON over `bincode` / a custom packer: the only consumer is
// the local SQLite database. Wire-format stability lives on the
// Rust side under `tests/wire_stability.rs`; SQLite columns are
// re-readable as long as the converter on either side of a schema
// migration agrees. Gson loses some round-trip precision on
// `Map<String, *>` but every consumer of `Message.reactions` /
// `Conversation.participants` already treats them as opaque
// presentation lists, so it doesn't matter.
class Converters {

    private val gson = Gson()

    // --- Enums -----------------------------------------------------

    @TypeConverter
    fun trustLevelToString(value: TrustLevel?): String? = value?.name

    @TypeConverter
    fun stringToTrustLevel(value: String?): TrustLevel? =
        value?.let { runCatching { TrustLevel.valueOf(it) }.getOrNull() }

    @TypeConverter
    fun verificationStatusToString(value: ContactVerificationStatus?): String? = value?.name

    @TypeConverter
    fun stringToVerificationStatus(value: String?): ContactVerificationStatus? =
        value?.let { runCatching { ContactVerificationStatus.valueOf(it) }.getOrNull() }

    @TypeConverter
    fun messageTypeToString(value: MessageType?): String? = value?.name

    @TypeConverter
    fun stringToMessageType(value: String?): MessageType? =
        value?.let { runCatching { MessageType.valueOf(it) }.getOrNull() }

    @TypeConverter
    fun messageStatusToString(value: MessageStatus?): String? = value?.name

    @TypeConverter
    fun stringToMessageStatus(value: String?): MessageStatus? =
        value?.let { runCatching { MessageStatus.valueOf(it) }.getOrNull() }

    @TypeConverter
    fun conversationTypeToString(value: ConversationType?): String? = value?.name

    @TypeConverter
    fun stringToConversationType(value: String?): ConversationType? =
        value?.let { runCatching { ConversationType.valueOf(it) }.getOrNull() }

    @TypeConverter
    fun keyTypeToString(value: KeyType?): String? = value?.name

    @TypeConverter
    fun stringToKeyType(value: String?): KeyType? =
        value?.let { runCatching { KeyType.valueOf(it) }.getOrNull() }

    // --- Collections ----------------------------------------------

    @TypeConverter
    fun stringListToJson(value: List<String>?): String? = value?.let { gson.toJson(it) }

    @TypeConverter
    fun jsonToStringList(value: String?): List<String>? = value?.let {
        runCatching {
            gson.fromJson<List<String>>(it, object : TypeToken<List<String>>() {}.type)
        }.getOrNull()
    }

    @TypeConverter
    fun reactionsToJson(value: Map<String, List<String>>?): String? =
        value?.let { gson.toJson(it) }

    @TypeConverter
    fun jsonToReactions(value: String?): Map<String, List<String>>? = value?.let {
        runCatching {
            gson.fromJson<Map<String, List<String>>>(
                it,
                object : TypeToken<Map<String, List<String>>>() {}.type,
            )
        }.getOrNull()
    }
}
