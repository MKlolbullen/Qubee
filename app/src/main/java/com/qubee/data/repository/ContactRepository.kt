package com.qubee.messenger.data.repository

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import com.qubee.messenger.data.database.dao.ContactDao
import com.qubee.messenger.data.database.dao.CryptoKeyDao
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactWithLastMessage
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.model.CryptoKey
import com.qubee.messenger.data.model.KeyType
import com.qubee.messenger.crypto.QubeeManager
import timber.log.Timber
import java.util.Date
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ContactRepository @Inject constructor(
    private val contactDao: ContactDao,
    private val cryptoKeyDao: CryptoKeyDao,
    private val qubeeManager: QubeeManager
) {

    fun getAllContacts(): Flow<List<Contact>> = contactDao.getAllContacts()

    fun getBlockedContacts(): Flow<List<Contact>> = contactDao.getBlockedContacts()

    fun getContactsWithLastMessage(): Flow<List<ContactWithLastMessage>> = 
        contactDao.getContactsWithLastMessage()

    suspend fun getContactById(contactId: String): Contact? = contactDao.getContactById(contactId)

    suspend fun getContactByPhoneNumber(phoneNumber: String): Contact? = 
        contactDao.getContactByPhoneNumber(phoneNumber)

    suspend fun getContactByEmail(email: String): Contact? = contactDao.getContactByEmail(email)

    suspend fun searchContacts(query: String): List<Contact> = contactDao.searchContacts(query)

    suspend fun getContactsByTrustLevel(trustLevel: TrustLevel): List<Contact> = 
        contactDao.getContactsByTrustLevel(trustLevel)

    suspend fun getOnlineContacts(): List<Contact> = contactDao.getOnlineContacts()

    suspend fun addContact(
        displayName: String,
        phoneNumber: String? = null,
        email: String? = null,
        publicKey: ByteArray,
        identityKey: ByteArray
    ): Result<Contact> {
        return try {
            val contactId = generateContactId(publicKey)
            val contact = Contact(
                id = contactId,
                displayName = displayName,
                phoneNumber = phoneNumber,
                email = email,
                publicKey = publicKey,
                identityKey = identityKey,
                trustLevel = TrustLevel.TOFU,
                createdAt = Date(),
                updatedAt = Date()
            )

            contactDao.insertContact(contact)

            // Store the identity key
            val identityKeyRecord = CryptoKey(
                contactId = contactId,
                keyType = KeyType.IDENTITY,
                keyData = identityKey,
                createdAt = Date()
            )
            cryptoKeyDao.insertKey(identityKeyRecord)

            Timber.d("Added new contact: $displayName ($contactId)")
            Result.success(contact)
        } catch (e: Exception) {
            Timber.e(e, "Failed to add contact: $displayName")
            Result.failure(e)
        }
    }

    suspend fun updateContact(contact: Contact): Result<Unit> {
        return try {
            val updatedContact = contact.copy(updatedAt = Date())
            contactDao.updateContact(updatedContact)
            Timber.d("Updated contact: ${contact.displayName}")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update contact: ${contact.displayName}")
            Result.failure(e)
        }
    }

    suspend fun updateTrustLevel(contactId: String, trustLevel: TrustLevel): Result<Unit> {
        return try {
            contactDao.updateTrustLevel(contactId, trustLevel)
            Timber.d("Updated trust level for contact $contactId to $trustLevel")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update trust level for contact $contactId")
            Result.failure(e)
        }
    }

    suspend fun blockContact(contactId: String): Result<Unit> {
        return try {
            contactDao.updateBlockedStatus(contactId, true)
            Timber.d("Blocked contact: $contactId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to block contact: $contactId")
            Result.failure(e)
        }
    }

    suspend fun unblockContact(contactId: String): Result<Unit> {
        return try {
            contactDao.updateBlockedStatus(contactId, false)
            Timber.d("Unblocked contact: $contactId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to unblock contact: $contactId")
            Result.failure(e)
        }
    }

    suspend fun updateOnlineStatus(contactId: String, isOnline: Boolean, lastSeen: Date? = null): Result<Unit> {
        return try {
            contactDao.updateOnlineStatus(contactId, isOnline, lastSeen?.time)
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update online status for contact $contactId")
            Result.failure(e)
        }
    }

    suspend fun updateProfilePicture(contactId: String, profilePictureUrl: String?): Result<Unit> {
        return try {
            contactDao.updateProfilePicture(contactId, profilePictureUrl)
            Timber.d("Updated profile picture for contact $contactId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to update profile picture for contact $contactId")
            Result.failure(e)
        }
    }

    suspend fun verifyContactIdentity(contactId: String, verificationData: ByteArray): Result<Boolean> {
        return try {
            val contact = contactDao.getContactById(contactId)
                ?: return Result.failure(Exception("Contact not found"))

            val isValid = qubeeManager.verifyIdentityKey(
                contactId,
                contact.identityKey,
                verificationData
            )

            if (isValid) {
                updateTrustLevel(contactId, TrustLevel.VERIFIED)
                Timber.d("Successfully verified identity for contact $contactId")
            } else {
                updateTrustLevel(contactId, TrustLevel.COMPROMISED)
                Timber.w("Identity verification failed for contact $contactId")
            }

            Result.success(isValid)
        } catch (e: Exception) {
            Timber.e(e, "Error verifying identity for contact $contactId")
            Result.failure(e)
        }
    }

    suspend fun generateSASForContact(contactId: String): Result<String> {
        return try {
            val contact = contactDao.getContactById(contactId)
                ?: return Result.failure(Exception("Contact not found"))

            // Get our own identity key (this would be stored somewhere)
            val ourIdentityKey = getOurIdentityKey()
                ?: return Result.failure(Exception("Our identity key not found"))

            val sas = qubeeManager.generateSAS(ourIdentityKey, contact.identityKey)
                ?: return Result.failure(Exception("Failed to generate SAS"))

            Timber.d("Generated SAS for contact $contactId")
            Result.success(sas)
        } catch (e: Exception) {
            Timber.e(e, "Failed to generate SAS for contact $contactId")
            Result.failure(e)
        }
    }

    suspend fun deleteContact(contactId: String): Result<Unit> {
        return try {
            // Delete all crypto keys for this contact
            cryptoKeyDao.deleteAllKeysForContact(contactId)
            
            // Delete the contact
            contactDao.deleteContactById(contactId)
            
            Timber.d("Deleted contact: $contactId")
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to delete contact: $contactId")
            Result.failure(e)
        }
    }

    suspend fun getContactCount(): Int = contactDao.getContactCount()

    suspend fun getBlockedContactCount(): Int = contactDao.getBlockedContactCount()

    suspend fun getContactCountByTrustLevel(trustLevel: TrustLevel): Int = 
        contactDao.getContactCountByTrustLevel(trustLevel)

    private fun generateContactId(publicKey: ByteArray): String {
        // Generate a unique contact ID based on the public key
        return android.util.Base64.encodeToString(
            publicKey.sliceArray(0..15), // Use first 16 bytes
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP
        )
    }

    private suspend fun getOurIdentityKey(): ByteArray? {
        // This should retrieve our own identity key from secure storage
        // For now, return null - this would be implemented based on how we store our own keys
        return null
    }
}

