package com.qubee.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.MessageRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
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
    private val qubeeManager: QubeeManager
) : ViewModel() {

    // Retrieve the contactId from the navigation arguments
    private val contactId: String = checkNotNull(savedStateHandle["contactId"])
    
    // UI State that combines contact information and the message list
    val uiState: StateFlow<ChatUiState> = combine(
        contactRepository.getContactFlow(contactId),
        messageRepository.getMessagesForSession("session_$contactId") // Simplified session mapping
    ) { contact, messages ->
        ChatUiState(
            contactName = contact?.name ?: "Unknown",
            messages = messages.map { msg ->
                UiMessage(
                    id = msg.id,
                    text = msg.content, // Assuming the DB stores plaintext after decryption
                    isFromMe = msg.isFromMe,
                    timestamp = msg.timestamp,
                    type = UiMessageType.TEXT // Expand DB to support images/files in the future
                )
            }
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ChatUiState(contactName = "Loading...", messages = emptyList())
    )

    /**
     * Encrypts and sends a text message to the current contact.
     */
    fun sendMessage(text: String) {
        if (text.isBlank()) return
        
        viewModelScope.launch {
            try {
                // In a real app, you would look up the correct Session ID for this contact
                val sessionId = "session_$contactId"

                // 1. Encrypt the message using Rust (Kyber/Dilithium)
                val encrypted = qubeeManager.encryptMessage(sessionId, text)
                
                if (encrypted != null) {
                    // 2. Save to local database (marked as 'Sending' if status tracking exists)
                    messageRepository.saveMessage(sessionId, text, isFromMe = true)

                    // 3. Send via P2P Network
                    // This sends the encrypted blob into the swarm
                    val success = qubeeManager.sendP2PMessage(contactId, encrypted.toBytes())
                    
                    if (success) {
                        Timber.d("Message sent successfully via P2P to $contactId")
                    } else {
                        Timber.e("Failed to send message via P2P network")
                        // TODO: Update message status to FAILED in database
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
        // TODO: Implement file picker logic
    }
    
    fun onTakePhoto() { 
        Timber.d("Take photo clicked") 
        // TODO: Implement camera logic
    }
    
    fun onRecordAudio() { 
        Timber.d("Record audio clicked") 
        // TODO: Implement voice recorder logic
    }
}

// --- UI Data Models ---

data class ChatUiState(
    val contactName: String,
    val messages: List<UiMessage>
)

data class UiMessage(
    val id: String,
    val text: String,
    val isFromMe: Boolean,
    val timestamp: Long,
    val type: UiMessageType
)

enum class UiMessageType { TEXT, IMAGE, FILE, AUDIO }
