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

data class UiMessage(
    val id: String = "",
    val text: String = "",
    val isFromMe: Boolean = false,
    val timestamp: Long = 0L,
    val type: UiMessageType = UiMessageType.TEXT,
)

enum class UiMessageType { TEXT, IMAGE, FILE, AUDIO }
