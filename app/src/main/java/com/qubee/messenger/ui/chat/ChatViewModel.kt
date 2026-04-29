package com.qubee.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.MessageRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

@HiltViewModel
class ChatViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val messageRepository: MessageRepository,
    private val contactRepository: ContactRepository,
    private val qubeeManager: QubeeManager,
) : ViewModel() {

    // Retrieve the contactId from the navigation arguments.
    private val contactId: String = checkNotNull(savedStateHandle["contactId"])

    // UI state combines contact information, local messages and the current
    // security posture for the conversation. The security state is still
    // conservative until the repository layer exposes verification/session
    // metadata; encrypted != identity-verified.
    val uiState: StateFlow<ChatUiState> = combine(
        contactRepository.getContactFlow(contactId),
        messageRepository.getMessagesForSession("session_$contactId"),
    ) { contact, messages ->
        val securityState = if (contact == null) {
            ConversationSecurityState.Unverified
        } else {
            ConversationSecurityState.PqSessionActive
        }

        ChatUiState(
            contactId = contactId,
            contactName = contact?.name ?: "Unknown peer",
            securityState = securityState,
            messages = messages.map { msg ->
                UiMessage(
                    id = msg.id,
                    text = msg.content,
                    isFromMe = msg.isFromMe,
                    timestamp = msg.timestamp,
                    type = UiMessageType.TEXT,
                    status = if (msg.isFromMe) {
                        MessageDeliveryState.Sent
                    } else {
                        MessageDeliveryState.Received
                    },
                )
            },
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ChatUiState(
            contactId = contactId,
            contactName = "Loading…",
            securityState = ConversationSecurityState.OfflineQueued,
            messages = emptyList(),
        ),
    )

    /**
     * Encrypts and sends a text message to the current contact.
     */
    fun sendMessage(text: String) {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return

        viewModelScope.launch {
            try {
                // In a real app, you would look up the correct Session ID for this contact.
                val sessionId = "session_$contactId"

                // 1. Encrypt the message using Rust (Kyber/Dilithium).
                val encrypted = qubeeManager.encryptMessage(sessionId, trimmed)

                if (encrypted != null) {
                    // 2. Save to local database. Next schema pass should store status
                    // explicitly: Encrypting -> Queued -> Sent -> Delivered/Failed.
                    messageRepository.saveMessage(sessionId, trimmed, isFromMe = true)

                    // 3. Send via P2P network.
                    val success = qubeeManager.sendP2PMessage(contactId, encrypted.toBytes())

                    if (success) {
                        Timber.d("Message sent successfully via P2P to $contactId")
                    } else {
                        Timber.e("Failed to send message via P2P network")
                        // TODO: Update message status to FAILED in database.
                    }
                } else {
                    Timber.e("Encryption failed - Message not sent")
                }
            } catch (e: Exception) {
                Timber.e(e, "Exception during sendMessage")
            }
        }
    }

    // --- Media Handler Placeholders ---

    fun onAttachFile() {
        Timber.d("Attach file clicked")
        // TODO: Implement file picker logic.
    }

    fun onTakePhoto() {
        Timber.d("Take photo clicked")
        // TODO: Implement camera logic.
    }

    fun onRecordAudio() {
        Timber.d("Record audio clicked")
        // TODO: Implement voice recorder logic.
    }
}

// --- UI Data Models ---

data class ChatUiState(
    val contactId: String,
    val contactName: String,
    val securityState: ConversationSecurityState,
    val messages: List<UiMessage>,
)

data class UiMessage(
    val id: String,
    val text: String,
    val isFromMe: Boolean,
    val timestamp: Long,
    val type: UiMessageType,
    val status: MessageDeliveryState,
)

enum class UiMessageType { TEXT, IMAGE, FILE, AUDIO }
