package com.qubee.messenger.data.database.dao

import androidx.room.*
import kotlinx.coroutines.flow.Flow
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactWithLastMessage
import com.qubee.messenger.data.model.TrustLevel

@Dao
interface ContactDao {

    @Query("SELECT * FROM contacts WHERE isBlocked = 0 ORDER BY displayName ASC")
    fun getAllContacts(): Flow<List<Contact>>

    @Query("SELECT * FROM contacts WHERE isBlocked = 1 ORDER BY displayName ASC")
    fun getBlockedContacts(): Flow<List<Contact>>

    @Query("SELECT * FROM contacts WHERE id = :contactId")
    suspend fun getContactById(contactId: String): Contact?

    @Query("SELECT * FROM contacts WHERE phoneNumber = :phoneNumber")
    suspend fun getContactByPhoneNumber(phoneNumber: String): Contact?

    @Query("SELECT * FROM contacts WHERE email = :email")
    suspend fun getContactByEmail(email: String): Contact?

    @Query("""
        SELECT c.*, m.content as lastMessageContent, m.timestamp as lastMessageTimestamp,
               COUNT(CASE WHEN m.status != 3 AND m.isFromMe = 0 THEN 1 END) as unreadCount
        FROM contacts c
        LEFT JOIN (
            SELECT conversationId, senderId, content, timestamp, status, isFromMe,
                   ROW_NUMBER() OVER (PARTITION BY conversationId ORDER BY timestamp DESC) as rn
            FROM messages
        ) m ON c.id = m.senderId AND m.rn = 1
        WHERE c.isBlocked = 0
        GROUP BY c.id
        ORDER BY COALESCE(m.timestamp, c.createdAt) DESC
    """)
    fun getContactsWithLastMessage(): Flow<List<ContactWithLastMessage>>

    @Query("SELECT * FROM contacts WHERE displayName LIKE '%' || :query || '%' OR phoneNumber LIKE '%' || :query || '%'")
    suspend fun searchContacts(query: String): List<Contact>

    @Query("SELECT * FROM contacts WHERE trustLevel = :trustLevel")
    suspend fun getContactsByTrustLevel(trustLevel: TrustLevel): List<Contact>

    @Query("SELECT * FROM contacts WHERE isOnline = 1")
    suspend fun getOnlineContacts(): List<Contact>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertContact(contact: Contact)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertContacts(contacts: List<Contact>)

    @Update
    suspend fun updateContact(contact: Contact)

    @Query("UPDATE contacts SET trustLevel = :trustLevel WHERE id = :contactId")
    suspend fun updateTrustLevel(contactId: String, trustLevel: TrustLevel)

    @Query("UPDATE contacts SET isBlocked = :isBlocked WHERE id = :contactId")
    suspend fun updateBlockedStatus(contactId: String, isBlocked: Boolean)

    @Query("UPDATE contacts SET isOnline = :isOnline, lastSeen = :lastSeen WHERE id = :contactId")
    suspend fun updateOnlineStatus(contactId: String, isOnline: Boolean, lastSeen: Long?)

    @Query("UPDATE contacts SET profilePictureUrl = :profilePictureUrl WHERE id = :contactId")
    suspend fun updateProfilePicture(contactId: String, profilePictureUrl: String?)

    @Delete
    suspend fun deleteContact(contact: Contact)

    @Query("DELETE FROM contacts WHERE id = :contactId")
    suspend fun deleteContactById(contactId: String)

    @Query("DELETE FROM contacts WHERE isBlocked = 1")
    suspend fun deleteAllBlockedContacts()

    @Query("SELECT COUNT(*) FROM contacts WHERE isBlocked = 0")
    suspend fun getContactCount(): Int

    @Query("SELECT COUNT(*) FROM contacts WHERE isBlocked = 1")
    suspend fun getBlockedContactCount(): Int

    @Query("SELECT COUNT(*) FROM contacts WHERE trustLevel = :trustLevel")
    suspend fun getContactCountByTrustLevel(trustLevel: TrustLevel): Int
}

