package com.qubee.messenger.ui.chat

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.MessageRepository
import com.qubee.messenger.network.P2PNetworkManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

@HiltViewModel
class ChatViewModel @Inject constructor(
    private val qubeeManager: QubeeManager,
    private val messageRepository: MessageRepository,
    private val p2pNetwork: P2PNetworkManager // Vår "serverless" transport
) : ViewModel() {

    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    val messages = _messages.asStateFlow()

    // Laddar meddelanden för en specifik session (kontakt)
    fun loadMessages(sessionId: String) {
        viewModelScope.launch {
            messageRepository.getMessagesForSession(sessionId).collect { dbMessages ->
                // Här skulle vi normalt mappa om DB-objekt till UI-objekt
                // _messages.value = dbMessages.map { ... }
            }
        }
    }

    fun sendMessage(sessionId: String, contactNetworkAddress: String, plaintext: String) {
        viewModelScope.launch {
            try {
                // 1. Kryptera meddelandet lokalt med Rust (Hybrid Ratchet)
                val encryptedMessage = qubeeManager.encryptMessage(sessionId, plaintext)

                if (encryptedMessage != null) {
                    // 2. Spara det krypterade meddelandet i lokal DB (Outbox)
                    messageRepository.saveMessage(sessionId, plaintext, isFromMe = true)

                    // 3. Skicka direkt till mottagaren (P2P)
                    // Vi skickar inte via en server, utan direkt till deras IP/Address
                    val success = p2pNetwork.sendDirect(
                        address = contactNetworkAddress, 
                        payload = encryptedMessage.toBytes()
                    )

                    if (!success) {
                        Timber.e("Mottagaren är offline eller onåbar (P2P-fail)")
                        // Uppdatera UI att meddelandet väntar (köas)
                    }
                }
            } catch (e: Exception) {
                Timber.e(e, "Kunde inte skicka meddelande")
            }
        }
    }

    // Lyssnar på inkommande P2P-trafik
    init {
        viewModelScope.launch {
            p2pNetwork.incomingMessages.collect { (senderAddress, payload) ->
                // När vi tar emot data direkt från en peer:
                // 1. Identifiera session baserat på senderAddress eller payload metadata
                val sessionId = resolveSession(senderAddress)
                
                // 2. Dekryptera med Rust
                // OBS: EncryptedMessage.fromBytes måste implementeras i Kotlin-sidan
                val encryptedObj = com.qubee.messenger.crypto.EncryptedMessage.fromBytes(payload)
                
                if (encryptedObj != null) {
                    val decryptedText = qubeeManager.decryptMessage(sessionId, encryptedObj)
                    
                    if (decryptedText != null) {
                        messageRepository.saveMessage(sessionId, decryptedText, isFromMe = false)
                    }
                }
            }
        }
    }
    
    private fun resolveSession(address: String): String {
        // Logik för att mappa IP/Address till ett SessionID i databasen
        return "session_xyz" 
    }
}

// En enkel datamodell för UI
data class UiMessage(
    val id: String,
    val text: String,
    val isFromMe: Boolean,
    val timestamp: Long
)
