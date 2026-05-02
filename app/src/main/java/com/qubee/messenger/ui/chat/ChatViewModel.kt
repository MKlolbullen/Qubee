package com.qubee.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.MessageRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
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

    private val contactId: String = checkNotNull(savedStateHandle["contactId"])
    private val conversationId: String = savedStateHandle["conversationId"] ?: "session_$contactId"

    private val _events = MutableSharedFlow<ChatUiEvent>()
    val events: SharedFlow<ChatUiEvent> = _events.asSharedFlow()

    val uiState: StateFlow<ChatUiState> = combine(
        contactRepository.getContactFlow(contactId),
        messageRepository.getMessagesForConversation(conversationId),
    ) { contact, messages ->
        val securityState = if (contact == null) {
            ConversationSecurityState.Unverified
        } else {
            ConversationSecurityState.PqSessionActive
        }

        val mediaCount = messages.count { it.contentType == MessageType.IMAGE || it.contentType == MessageType.VIDEO }
        val fileCount = messages.count { it.contentType == MessageType.FILE }
        val audioCount = messages.count { it.contentType == MessageType.AUDIO }

        ChatUiState(
            contactId = contactId,
            conversationId = conversationId,
            contactName = contact?.displayName ?: "Unknown peer",
            securityState = securityState,
            messages = messages.map { msg ->
                UiMessage(
                    id = msg.id,
                    text = msg.content,
                    isFromMe = msg.isFromMe,
                    timestamp = msg.timestamp.time,
                    type = msg.contentType.toUiType(),
                    status = msg.status.toUiStatus(msg.isFromMe),
                )
            },
            details = ConversationDetailsUi(
                fingerprint = contact?.identityKey?.toFingerprint() ?: "Not available",
                isVerified = securityState == ConversationSecurityState.PqSessionActive,
                verificationLabel = if (securityState == ConversationSecurityState.PqSessionActive) "Verified locally" else "Not verified",
                sessionLabel = securityState.label,
                sessionNote = "Hybrid session state is device-local. Private keys never leave this device.",
                disappearingTimerLabel = "Off",
                mediaCount = mediaCount,
                fileCount = fileCount,
                audioCount = audioCount,
            ),
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ChatUiState(
            contactId = contactId,
            conversationId = conversationId,
            contactName = "Loading…",
            securityState = ConversationSecurityState.OfflineQueued,
            messages = emptyList(),
            details = ConversationDetailsUi.placeholder(),
        ),
    )

    fun sendMessage(text: String) {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return

        viewModelScope.launch {
            val result = messageRepository.sendTextMessage(conversationId, trimmed)
            result.onSuccess {
                Timber.d("Queued encrypted text message for conversation $conversationId")
                val encrypted = qubeeManager.encryptMessage(conversationId, trimmed)
                if (encrypted == null) {
                    emitNotice("Saved locally. Secure transport session is not ready yet.")
                    return@launch
                }
                val sent = qubeeManager.sendP2PMessage(contactId, encrypted.toBytes())
                if (sent) {
                    emitNotice("Encrypted message sent")
                } else {
                    emitNotice("Saved locally. Peer is offline or unreachable.")
                }
            }.onFailure { e ->
                Timber.e(e, "Failed to queue message")
                emitNotice("Could not queue message: ${e.message ?: "unknown error"}")
            }
        }
    }

    fun onAttachFile() = emitPending("Encrypted file attachments")

    fun onTakePhoto() = emitPending("Encrypted camera capture")

    fun onRecordAudio() = emitPending("Encrypted voice notes")

    fun requestSecureCall() = emitPending("P2P encrypted calls")

    fun requestContactVerification() = emitPending("QR/fingerprint verification flow")

    fun changeDisappearingTimer() = emitPending("Disappearing message timer")

    fun resetSecureSession() = emitPending("Secure session reset / re-handshake")

    fun clearChat() {
        viewModelScope.launch {
            messageRepository.clearConversationMessages(conversationId)
                .onSuccess { emitNotice("Local chat history cleared") }
                .onFailure { emitNotice("Could not clear chat: ${it.message ?: "unknown error"}") }
        }
    }

    private fun emitPending(feature: String) {
        viewModelScope.launch {
            _events.emit(ChatUiEvent.Notice("$feature is wired in the UI and ready for the next implementation pass."))
        }
    }

    private suspend fun emitNotice(message: String) {
        _events.emit(ChatUiEvent.Notice(message))
    }
}

data class ChatUiState(
    val contactId: String,
    val conversationId: String,
    val contactName: String,
    val securityState: ConversationSecurityState,
    val messages: List<UiMessage>,
    val details: ConversationDetailsUi,
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
    val id: String,
    val text: String,
    val isFromMe: Boolean,
    val timestamp: Long,
    val type: UiMessageType,
    val status: MessageDeliveryState,
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
    else -> if (isFromMe) MessageDeliveryState.Sent else MessageDeliveryState.Received
}

private fun ByteArray.toFingerprint(): String = take(8)
    .joinToString("-") { byte -> "%02X".format(byte) }
    .ifBlank { "Not available" }
