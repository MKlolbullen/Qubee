package com.qubee.messenger.data.repository

import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageWithSender
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

// Pre-alpha placeholder — see ContactRepository for the rationale.

@Singleton
class MessageRepository @Inject constructor() {

    fun getMessagesForSession(sessionId: String): Flow<List<MessageWithSender>> =
        MutableStateFlow<List<MessageWithSender>>(emptyList()).asStateFlow()

    fun getTotalUnreadMessageCount(): Flow<Int> = MutableStateFlow(0).asStateFlow()

    suspend fun saveMessage(message: Message) {}
    suspend fun cleanupExpiredMessages() {}

    companion object {
        @Volatile private var INSTANCE: MessageRepository? = null
        fun getInstance(): MessageRepository =
            INSTANCE ?: synchronized(this) { INSTANCE ?: MessageRepository().also { INSTANCE = it } }
    }
}
