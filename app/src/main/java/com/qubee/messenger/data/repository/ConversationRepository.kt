package com.qubee.messenger.data.repository

import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationWithDetails
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

// Pre-alpha placeholder — see ContactRepository for the rationale.

@Singleton
class ConversationRepository @Inject constructor() {

    fun getAllConversations(): Flow<List<Conversation>> =
        MutableStateFlow<List<Conversation>>(emptyList()).asStateFlow()
    fun getConversationsWithDetails(): Flow<List<ConversationWithDetails>> =
        MutableStateFlow<List<ConversationWithDetails>>(emptyList()).asStateFlow()

    suspend fun getOrCreateConversationId(contactId: String): String = ""
    suspend fun getConversationById(id: String): Conversation? = null

    companion object {
        @Volatile private var INSTANCE: ConversationRepository? = null
        fun getInstance(): ConversationRepository =
            INSTANCE ?: synchronized(this) { INSTANCE ?: ConversationRepository().also { INSTANCE = it } }
    }
}
