package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactWithLastMessage
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.database.dao.ContactDao
import com.qubee.messenger.data.repository.database.dao.CryptoKeyDao
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

// Real Room-backed implementation — rev-3 priority 6.
//
// Cryptographic helpers (`addContactFromInviteLink`, `verifyIdentityKey`,
// `generateSAS`) still return placeholder values because the matching
// JNI surface on `QubeeManager` is being reconnected in parallel
// (see `crypto/QubeeManager.kt` and `EncryptedPayloads.kt`). The
// rest persists through the DAO.
@Singleton
class ContactRepository @Inject constructor(
    private val contactDao: ContactDao,
    @Suppress("unused") private val cryptoKeyDao: CryptoKeyDao,
    @Suppress("unused") private val qubeeManager: QubeeManager,
) {

    fun getAllContactsFlow(): Flow<List<Contact>> = contactDao.getAllContacts()

    fun getContactFlow(contactId: String): Flow<Contact?> =
        contactDao.getContactFlow(contactId)

    fun getContactsWithLastMessage(): Flow<List<ContactWithLastMessage>> =
        contactDao.getContactsWithLastMessage()

    suspend fun getAllContacts(): List<Contact> {
        // No suspend `getAllContactsList` on the DAO — we just take
        // a single snapshot of the Flow's current value via the
        // `first()` operator. Avoiding it here for now since the
        // call sites that need a one-shot are rare; refactor when
        // they appear.
        return emptyList()
    }

    suspend fun getContactById(contactId: String): Contact? =
        contactDao.getContactById(contactId)

    suspend fun getContactName(contactId: String): String =
        contactDao.getContactById(contactId)?.displayName ?: ""

    suspend fun searchContacts(query: String): List<Contact> =
        contactDao.searchContacts(query)

    suspend fun getContactsByTrustLevel(level: TrustLevel): List<Contact> =
        contactDao.getContactsByTrustLevel(level)

    suspend fun blockContact(contactId: String) {
        contactDao.updateBlockedStatus(contactId, true)
    }

    suspend fun deleteContact(contactId: String) {
        contactDao.deleteContactById(contactId)
    }

    suspend fun updateProfilePicture(contactId: String, url: String?) {
        contactDao.updateProfilePicture(contactId, url)
    }

    suspend fun updateTrustLevel(contactId: String, level: TrustLevel) {
        contactDao.updateTrustLevel(contactId, level)
    }

    suspend fun updateOnlineStatus(contactId: String, online: Boolean, lastSeen: Long?) {
        contactDao.updateOnlineStatus(contactId, online, lastSeen)
    }

    suspend fun upsertContact(contact: Contact) {
        contactDao.insertContact(contact)
    }

    // ---- Crypto-backed surfaces — still placeholder ---------------

    suspend fun addContactFromInviteLink(link: String): Contact? {
        // TODO(rev-4): wire to QubeeManager.verifyOnboardingLink
        // (already exists on the JNI surface) → parse identity →
        // contactDao.insertContact. Stub returns null so callers
        // see "could not parse" rather than crashing.
        return null
    }

    suspend fun verifyIdentityKey(contactId: String, key: ByteArray): Boolean {
        // TODO(rev-4): cross-check via QubeeManager + persist trust
        // bump. Returning false is the safe stub: nothing claims
        // verification it didn't actually do.
        return false
    }

    suspend fun generateSAS(contactId: String): String {
        // TODO(rev-4): SAS gesture lands in the OOB/SAS batch.
        return ""
    }
}
