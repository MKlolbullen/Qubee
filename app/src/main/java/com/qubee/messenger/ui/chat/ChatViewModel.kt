package com.qubee.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

// Pre-alpha placeholder. Real chat persistence (MessageRepository,
// ContactRepository over Room) is on the post-alpha track. The
// ViewModel exists so ChatScreen.kt + ChatFragment compile and
// render an empty conversation.

@HiltViewModel
class ChatViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val contactId: String = savedStateHandle["contactId"] ?: ""

    private val _uiState = MutableStateFlow(ChatUiState(contactName = contactId))
    val uiState: StateFlow<ChatUiState> = _uiState.asStateFlow()

    fun sendMessage(text: String) = Unit
    fun onAttachFile() = Unit
    fun onTakePhoto() = Unit
    fun onRecordAudio() = Unit
}

data class ChatUiState(
    val contactName: String = "",
    val messages: List<UiMessage> = emptyList(),
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
