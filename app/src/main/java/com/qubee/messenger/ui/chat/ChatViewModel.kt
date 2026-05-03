package com.qubee.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.MessageRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

// Real chat surface ViewModel — rev-3 priority 7. Wires
// `MessageRepository` (Flow<List<MessageWithSender>>) and
// `ContactRepository` into the surface that `ChatScreen.kt`
// consumes (`uiState.details`, `uiState.securityState`,
// `events`, plus the action methods `requestSecureCall`,
// `requestContactVerification`, `changeDisappearingTimer`,
// `resetSecureSession`, `clearChat`).
//
// The actual message-pipeline JNI surface (`encryptMessage` /
// `decryptMessage`) is being reconnected in parallel — see
// `crypto/QubeeManager.kt` and the comment block in
// `src/jni_api.rs`. Until that lands, `sendMessage` writes a
// `MessageStatus.SENDING` row through the repository and surfaces
// a `ChatUiEvent.Notice` rather than calling into the Rust core.
@HiltViewModel
class ChatViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val messageRepository: MessageRepository,
    private val contactRepository: ContactRepository,
    private val conversationRepository: ConversationRepository,
    @Suppress("unused") private val qubeeManager: QubeeManager,
) : ViewModel() {

    private val contactId: String = savedStateHandle["contactId"] ?: ""

    private val _uiState = MutableStateFlow(
        ChatUiState(
            contactName = contactId.take(8),
            details = ConversationDetailsUi.placeholder(),
        ),
    )
    val uiState: StateFlow<ChatUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<ChatUiEvent>(extraBufferCapacity = 4)
    val events: SharedFlow<ChatUiEvent> = _events.asSharedFlow()

    private var conversationId: String = ""

    init {
        viewModelScope.launch {
            // Resolve the conversation row + contact metadata first
            // so subsequent sendMessage calls have a target to write
            // to, then start streaming messages.
            conversationId = conversationRepository.getOrCreateConversationId(contactId)
            val contact = contactRepository.getContactById(contactId)
            val name = contact?.displayName?.takeIf { it.isNotBlank() } ?: contactId.take(8)

            val initialDetails = ConversationDetailsUi.placeholder().copy(
                fingerprint = (contact?.identityKey?.toFingerprint() ?: "Not available"),
                isVerified = false,
                verificationLabel = if (contact == null) "Unknown" else "Unverified",
            )
            _uiState.value = _uiState.value.copy(
                contactName = name,
                details = initialDetails,
            )

            messageRepository
                .getMessagesForConversation(conversationId)
                .map { rows -> rows.map { it.toUi() } }
                .collect { uiMessages ->
                    _uiState.value = _uiState.value.copy(messages = uiMessages)
                }
        }
    }

    // ---- Send / actions -------------------------------------------

    fun sendMessage(text: String) {
        val payload = text.trim()
        if (payload.isEmpty() || conversationId.isEmpty()) return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            val message = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = SELF_SENDER_ID,
                content = payload,
                contentType = MessageType.TEXT,
                timestamp = now,
                status = MessageStatus.SENDING,
                isFromMe = true,
            )
            messageRepository.saveMessage(message)
            // TODO(rev-4): plug QubeeManager.sendP2PMessage into the
            // Rust message pipeline; bump status to SENT / FAILED on
            // the JNI callback.
            _events.emit(ChatUiEvent.Notice("Message queued (P2P delivery not yet connected)"))
        }
    }

    fun onAttachFile() = notice("Attachments not yet implemented")
    fun onTakePhoto() = notice("Camera capture not yet implemented")
    fun onRecordAudio() = notice("Voice messages not yet implemented")
    fun requestSecureCall() = notice("Secure calling lands post-alpha (calling feature flag)")
    fun requestContactVerification() = notice("Verification gesture lands in the next batch")
    fun changeDisappearingTimer() = notice("Disappearing-timer UI not yet wired")
    fun resetSecureSession() = notice("Session reset not yet wired to the Rust core")

    fun clearChat() {
        if (conversationId.isEmpty()) return
        viewModelScope.launch {
            messageRepository.deleteAllMessagesForConversation(conversationId)
            _events.emit(ChatUiEvent.Notice("Chat cleared on this device"))
        }
    }

    private fun notice(message: String) {
        viewModelScope.launch { _events.emit(ChatUiEvent.Notice(message)) }
    }

    private fun com.qubee.messenger.data.model.MessageWithSender.toUi(): UiMessage {
        val msg = this.message
        return UiMessage(
            id = msg.id,
            text = msg.content,
            isFromMe = msg.isFromMe,
            timestamp = msg.timestamp,
            type = msg.contentType.toUiType(),
            status = msg.status.toUiStatus(msg.isFromMe),
        )
    }

    private companion object {
        // TODO(rev-4): replace with the local user's IdentityId once
        // QubeeManager exposes a stable accessor for it (the
        // onboarding bundle plumbs it but doesn't surface it as a
        // dedicated JNI getter yet).
        const val SELF_SENDER_ID: String = "self"
    }
}

data class ChatUiState(
    val contactName: String = "",
    val messages: List<UiMessage> = emptyList(),
    val details: ConversationDetailsUi = ConversationDetailsUi.placeholder(),
    val securityState: ConversationSecurityState = ConversationSecurityState.Unverified,
)

data class ConversationDetailsUi(
    val fingerprint: String,
    val isVerified: Boolean,
    val verificationLabel: String,
    val sessionLabel: String,
    val sessionNote: String,
    val disappearingTimerLabel: String,
    val mediaCount: Int,
    val fileCount: Int,
    val audioCount: Int,
) {
    companion object {
        fun placeholder() = ConversationDetailsUi(
            fingerprint = "Loading…",
            isVerified = false,
            verificationLabel = "Checking",
            sessionLabel = "Loading session",
            sessionNote = "Inspecting local session state.",
            disappearingTimerLabel = "Off",
            mediaCount = 0,
            fileCount = 0,
            audioCount = 0,
        )
    }
}

data class UiMessage(
    val id: String = "",
    val text: String = "",
    val isFromMe: Boolean = false,
    val timestamp: Long = 0L,
    val type: UiMessageType = UiMessageType.TEXT,
    val status: MessageDeliveryState = MessageDeliveryState.Sent,
)

enum class UiMessageType { TEXT, IMAGE, FILE, AUDIO }

sealed class ChatUiEvent {
    data class Notice(val message: String) : ChatUiEvent()
}

private fun MessageType.toUiType(): UiMessageType = when (this) {
    MessageType.TEXT -> UiMessageType.TEXT
    MessageType.IMAGE, MessageType.VIDEO -> UiMessageType.IMAGE
    MessageType.FILE -> UiMessageType.FILE
    MessageType.AUDIO, MessageType.VOICE -> UiMessageType.AUDIO
}

private fun MessageStatus.toUiStatus(isFromMe: Boolean): MessageDeliveryState = when (this) {
    MessageStatus.SENDING -> MessageDeliveryState.Queued
    MessageStatus.SENT -> MessageDeliveryState.Sent
    MessageStatus.DELIVERED -> MessageDeliveryState.Delivered
    MessageStatus.READ -> MessageDeliveryState.Delivered
    MessageStatus.FAILED -> MessageDeliveryState.Failed
}

private fun ByteArray.toFingerprint(): String = take(8)
    .joinToString("-") { byte -> "%02X".format(byte) }
    .ifBlank { "Not available" }
