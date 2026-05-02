package com.qubee.messenger.data.repository

import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactWithLastMessage
import com.qubee.messenger.data.model.TrustLevel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

// Pre-alpha placeholder. Real persistence (Room DAOs, encrypted storage)
// hasn't been wired yet — see the pre-alpha plan A4. Methods return
// empty results / no-op so the half-built ViewModels and Fragments
// compile against a stable surface.

@Singleton
class ContactRepository @Inject constructor() {

    private val emptyFlow = MutableStateFlow<List<Contact>>(emptyList())

    fun getAllContactsFlow(): Flow<List<Contact>> = emptyFlow.asStateFlow()
    fun getContactFlow(contactId: String): Flow<Contact?> = MutableStateFlow<Contact?>(null).asStateFlow()
    fun getContactsWithLastMessage(): Flow<List<ContactWithLastMessage>> = MutableStateFlow<List<ContactWithLastMessage>>(emptyList()).asStateFlow()

    suspend fun getAllContacts(): List<Contact> = emptyList()
    suspend fun getContactById(contactId: String): Contact? = null
    suspend fun getContactName(contactId: String): String = ""
    suspend fun searchContacts(query: String): List<Contact> = emptyList()
    suspend fun getContactsByTrustLevel(level: TrustLevel): List<Contact> = emptyList()

    suspend fun addContactFromInviteLink(link: String): Contact? = null
    suspend fun blockContact(contactId: String) {}
    suspend fun deleteContact(contactId: String) {}
    suspend fun verifyIdentityKey(contactId: String, key: ByteArray): Boolean = false
    suspend fun generateSAS(contactId: String): String = ""
    suspend fun updateProfilePicture(contactId: String, url: String?) {}
    suspend fun updateTrustLevel(contactId: String, level: TrustLevel) {}
    suspend fun updateOnlineStatus(contactId: String, online: Boolean, lastSeen: Long?) {}

    companion object {
        @Volatile private var INSTANCE: ContactRepository? = null
        fun getInstance(): ContactRepository =
            INSTANCE ?: synchronized(this) { INSTANCE ?: ContactRepository().also { INSTANCE = it } }
    }
}
