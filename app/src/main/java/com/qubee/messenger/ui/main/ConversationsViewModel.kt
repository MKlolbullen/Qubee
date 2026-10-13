package com.qubee.messenger.ui.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.data.model.ConversationWithDetails
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.ui.theme.QubeeTrust
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class ConversationsViewModel @Inject constructor(
    conversationRepository: ConversationRepository,
    contactRepository: ContactRepository,
) : ViewModel() {

    val uiState: StateFlow<ConversationsUiState> = combine(
        conversationRepository.getConversationsWithDetails(),
        contactRepository.getAllContactsFlow(),
    ) { conversations, contacts ->
        val trustById = contacts.associate { it.id to QubeeTrust.of(it.trustLevel) }
        ConversationsUiState(
            conversations = conversations.map { it.toSummary(trustById) },
        )
    }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = ConversationsUiState(isLoading = true),
        )

    private fun ConversationWithDetails.toSummary(trustById: Map<String, QubeeTrust>): ConversationSummaryUi {
        val c = conversation
        // `participants` holds contact ids; the first non-self one is the
        // peer of a direct chat. Groups fall back to the conversation id.
        val peerId = c.participants
            .firstOrNull { it.isNotBlank() && it != "current_user_id" }
            ?: c.id
        val isGroup = c.type == ConversationType.GROUP
        val title = when {
            c.name.isNotBlank() -> c.name
            isGroup -> "Private group"
            else -> "Secure peer"
        }
        val preview = lastMessageContent
            ?.lineSequence()
            ?.map { it.trim() }
            ?.firstOrNull { it.isNotEmpty() }
            .orEmpty()
        val at = lastMessageTimestamp ?: c.lastMessageTimestamp ?: c.updatedAt

        return ConversationSummaryUi(
            conversationId = c.id,
            peerId = peerId,
            title = title,
            preview = preview,
            timestamp = formatTimestamp(at),
            isGroup = isGroup,
            isPinned = c.isPinned,
            isMuted = c.isMuted,
            unreadCount = unreadCount,
            trust = if (isGroup) null else trustById[peerId] ?: QubeeTrust.Unverified,
        )
    }
}

/** Today as a clock time, the past week as a weekday, anything older as a date. */
internal fun formatTimestamp(epochMillis: Long, now: Long = System.currentTimeMillis()): String {
    if (epochMillis <= 0L) return ""
    val locale = Locale.getDefault()
    val then = Calendar.getInstance().apply { timeInMillis = epochMillis }
    val today = Calendar.getInstance().apply { timeInMillis = now }
    val sameDay = then.get(Calendar.YEAR) == today.get(Calendar.YEAR) &&
        then.get(Calendar.DAY_OF_YEAR) == today.get(Calendar.DAY_OF_YEAR)
    val pattern = when {
        sameDay -> "HH:mm"
        now - epochMillis < 6L * 24 * 60 * 60 * 1000 -> "EEE"
        else -> "d MMM"
    }
    return SimpleDateFormat(pattern, locale).format(Date(epochMillis))
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
    /** Null for groups: trust is per member and lives in the group details. */
    val trust: QubeeTrust?,
)
