package com.qubee.messenger.ui.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.CallRepository
import com.qubee.messenger.data.repository.VerificationRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for the enhanced ContactsFragment
 */
class ContactsViewModel : ViewModel() {
    
    private val contactRepository = ContactRepository.getInstance()
    private val callRepository = CallRepository.getInstance()
    private val verificationRepository = VerificationRepository.getInstance()
    
    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts.asStateFlow()
    
    private val _loading = MutableStateFlow(false)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()
    
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()
    
    private val _verificationResult = MutableStateFlow<ContactVerificationResult?>(null)
    val verificationResult: StateFlow<ContactVerificationResult?> = _verificationResult.asStateFlow()
    
    private var allContacts: List<Contact> = emptyList()
    
    /**
     * Load all contacts from the repository
     */
    fun loadContacts() {
        viewModelScope.launch {
            _loading.value = true
            try {
                allContacts = contactRepository.getAllContacts()
                _contacts.value = allContacts
            } catch (e: Exception) {
                _error.value = "Failed to load contacts: ${e.message}"
            } finally {
                _loading.value = false
            }
        }
    }
    
    /**
     * Search contacts by name or metadata
     */
    fun searchContacts(query: String) {
        if (query.isBlank()) {
            _contacts.value = allContacts
            return
        }
        
        val filteredList = allContacts.filter {
            it.displayName.contains(query, ignoreCase = true)
                || it.metadata.notes.contains(query, ignoreCase = true)
                || it.metadata.tags.any { tag -> tag.contains(query, ignoreCase = true) }
        }
        _contacts.value = filteredList
    }
    
    /**
     * Filter contacts by trust level
     */
    fun filterByTrustLevel(trustLevels: List<TrustLevel>) {
        if (trustLevels.isEmpty()) {
            _contacts.value = allContacts
            return
        }
        
        val filteredList = allContacts.filter { trustLevels.contains(it.trustLevel) }
        _contacts.value = filteredList
    }
    
    /**
     * Add a new contact from an invite link
     */
    fun addContactFromInviteLink(inviteLink: String) {
        viewModelScope.launch {
            _loading.value = true
            try {
                contactRepository.addContactFromInviteLink(inviteLink)
                loadContacts() // Refresh list
            } catch (e: Exception) {
                _error.value = "Failed to add contact: ${e.message}"
            } finally {
                _loading.value = false
            }
        }
    }
    
    /**
     * Verify a contact using QR code data
     */
    fun verifyContactWithQR(qrData: String) {
        viewModelScope.launch {
            _loading.value = true
            try {
                val result = verificationRepository.verifyWithQRCode(qrData)
                _verificationResult.value = result
            } catch (e: Exception) {
                _error.value = "QR code verification failed: ${e.message}"
            } finally {
                _loading.value = false
            }
        }
    }
    
    /**
     * Verify a contact using NFC data
     */
    fun verifyContactWithNFC(nfcData: ByteArray) {
        viewModelScope.launch {
            _loading.value = true
            try {
                val result = verificationRepository.verifyWithNFC(nfcData)
                _verificationResult.value = result
            } catch (e: Exception) {
                _error.value = "NFC verification failed: ${e.message}"
            } finally {
                _loading.value = false
            }
        }
    }
    
    /**
     * Initiate a call with a contact
     */
    fun initiateCall(contactId: String, isVideo: Boolean) {
        viewModelScope.launch {
            try {
                callRepository.initiateCall(contactId, isVideo)
                // Navigate to call screen
            } catch (e: Exception) {
                _error.value = "Failed to initiate call: ${e.message}"
            }
        }
    }
    
    /**
     * Initiate a verification call with a contact
     */
    fun initiateVerificationCall(contactId: String) {
        viewModelScope.launch {
            try {
                callRepository.initiateVerificationCall(contactId)
                // Navigate to call screen with verification UI
            } catch (e: Exception) {
                _error.value = "Failed to initiate verification call: ${e.message}"
            }
        }
    }
    
    /**
     * Block a contact
     */
    fun blockContact(contactId: String) {
        viewModelScope.launch {
            try {
                contactRepository.blockContact(contactId)
                loadContacts() // Refresh list
            } catch (e: Exception) {
                _error.value = "Failed to block contact: ${e.message}"
            }
        }
    }
    
    /**
     * Delete a contact
     */
    fun deleteContact(contactId: String) {
        viewModelScope.launch {
            try {
                contactRepository.deleteContact(contactId)
                loadContacts() // Refresh list
            } catch (e: Exception) {
                _error.value = "Failed to delete contact: ${e.message}"
            }
        }
    }
    
    /**
     * Clear the current error message
     */
    fun clearError() {
        _error.value = null
    }
    
    /**
     * Clear the verification result
     */
    fun clearVerificationResult() {
        _verificationResult.value = null
    }
}
