package com.qubee.messenger.ui.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.data.repository.ConversationRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class ConversationsViewModel @Inject constructor(
    conversationRepository: ConversationRepository,
) : ViewModel() {

    val uiState: StateFlow<ConversationsUiState> = conversationRepository
        .getAllConversations()
        .map { conversations ->
            ConversationsUiState(
                conversations = conversations.map { it.toSummary() },
            )
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = ConversationsUiState(isLoading = true),
        )

    private fun Conversation.toSummary(): ConversationSummaryUi {
        // `participants` is a `List<String>` per `data.model.Conversation`,
        // not a JSON-encoded string. Pick the first non-self id;
        // fall back to the conversation id itself for groups.
        val peerId = participants
            .firstOrNull { it.isNotBlank() && it != "current_user_id" }
            ?: id

        val title = when {
            !name.isNullOrBlank() -> name
            type == ConversationType.GROUP -> "Private group"
            else -> "Secure peer"
        }

        val preview = when {
            type == ConversationType.GROUP -> "Group channel · post-quantum session"
            else -> "Direct channel · post-quantum session"
        }

        val timestamp = lastMessageTimestamp?.let { formatTime(it) }
            ?: formatTime(updatedAt)

        return ConversationSummaryUi(
            conversationId = id,
            peerId = peerId,
            title = title,
            preview = preview,
            timestamp = timestamp,
            isGroup = type == ConversationType.GROUP,
            isPinned = isPinned,
            isMuted = isMuted,
            unreadCount = 0,
            securityState = ConversationListSecurityState.PqReady,
        )
    }

    private fun formatTime(date: Date): String =
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)

    private fun formatTime(epochMillis: Long): String =
        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(epochMillis))
}

data class ConversationsUiState(
    val isLoading: Boolean = false,
    val conversations: List<ConversationSummaryUi> = emptyList(),
)

data class ConversationSummaryUi(
    val conversationId: String,
    val peerId: String,
    val title: String,
    val preview: String,
    val timestamp: String,
    val isGroup: Boolean,
    val isPinned: Boolean,
    val isMuted: Boolean,
    val unreadCount: Int,
    val securityState: ConversationListSecurityState,
)

enum class ConversationListSecurityState(val label: String) {
    PqReady("PQ READY"),
    Unverified("VERIFY"),
    Offline("QUEUED"),
}
