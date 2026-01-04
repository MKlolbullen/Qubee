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

    // Hämta contactId från navigation argumenten
    private val contactId: String = checkNotNull(savedStateHandle["contactId"])
    
    // UI State som kombinerar kontaktinfo och meddelanden
    val uiState: StateFlow<ChatUiState> = combine(
        contactRepository.getContactFlow(contactId),
        messageRepository.getMessagesForSession("session_$contactId") // Förenklad session-mappning
    ) { contact, messages ->
        ChatUiState(
            contactName = contact?.name ?: "Okänd",
            messages = messages.map { msg ->
                UiMessage(
                    id = msg.id,
                    text = msg.content, // Antar att DB sparar klartext efter dekryptering
                    isFromMe = msg.isFromMe,
                    timestamp = msg.timestamp,
                    type = UiMessageType.TEXT // Utöka DB för att stödja bild/fil
                )
            }
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ChatUiState(contactName = "Laddar...", messages = emptyList())
    )

    fun sendMessage(text: String) {
        if (text.isBlank()) return
        
        viewModelScope.launch {
            try {
                val sessionId = "session_$contactId"

                // 1. Kryptera meddelandet med Rust (Kyber/Dilithium)
                val encrypted = qubeeManager.encryptMessage(sessionId, text)
                
                if (encrypted != null) {
                    // 2. Spara i lokal DB (först som 'Sending' om vi hade status)
                    messageRepository.saveMessage(sessionId, text, isFromMe = true)

                    // 3. Skicka via P2P (Här behöver vi en ny metod i QubeeManager!)
                    // qubeeManager.sendP2PMessage(contactId, encrypted.toBytes())
                    Timber.d("Message encrypted & saved. Ready for P2P transport.")
                } else {
                    Timber.e("Encryption failed")
                }
            } catch (e: Exception) {
                Timber.e(e, "Failed to send message")
            }
        }
    }

    // Media handlers (Placeholder logic)
    fun onAttachFile() { Timber.d("Attach file clicked") }
    fun onTakePhoto() { Timber.d("Take photo clicked") }
    fun onRecordAudio() { Timber.d("Record audio clicked") }
}

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
