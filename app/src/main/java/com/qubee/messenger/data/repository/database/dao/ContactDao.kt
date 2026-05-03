package com.qubee.messenger.data.repository.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactWithLastMessage
import com.qubee.messenger.data.model.TrustLevel
import kotlinx.coroutines.flow.Flow

// Re-introduced in rev-3 priority 3. The rev-2 cleanup deleted the
// previous incarnation because its package declaration didn't match
// its file path and the underlying entities (Contact / etc.) were
// missing. Both fixed now: package matches the directory layout
// and the entities are real `@Entity` rows.
@Dao
interface ContactDao {

    @Query("SELECT * FROM contacts WHERE isBlocked = 0 ORDER BY displayName ASC")
    fun getAllContacts(): Flow<List<Contact>>

    @Query("SELECT * FROM contacts WHERE isBlocked = 1 ORDER BY displayName ASC")
    fun getBlockedContacts(): Flow<List<Contact>>

    @Query("SELECT * FROM contacts WHERE id = :contactId")
    fun getContactFlow(contactId: String): Flow<Contact?>

    @Query("SELECT * FROM contacts WHERE id = :contactId")
    suspend fun getContactById(contactId: String): Contact?

    @Query("SELECT * FROM contacts WHERE identityId = :identityId")
    suspend fun getContactByIdentityId(identityId: String): Contact?

    @Query("SELECT * FROM contacts WHERE phoneNumber = :phoneNumber")
    suspend fun getContactByPhoneNumber(phoneNumber: String): Contact?

    @Query("SELECT * FROM contacts WHERE email = :email")
    suspend fun getContactByEmail(email: String): Contact?

    // Aggregate read for the conversations list. Joins the latest
    // message per `senderId == contact.id` and counts unread inbound
    // messages. The unread-count subquery filters on `status != 3`
    // (the ordinal of `MessageStatus.READ` in the enum) and `isFromMe = 0`.
    @Query(
        """
        SELECT c.*,
               m.content as lastMessageContent,
               m.timestamp as lastMessageTimestamp,
               COUNT(CASE WHEN m.status != 'READ' AND m.isFromMe = 0 THEN 1 END) as unreadCount
        FROM contacts c
        LEFT JOIN (
            SELECT conversationId, senderId, content, timestamp, status, isFromMe,
                   ROW_NUMBER() OVER (PARTITION BY conversationId ORDER BY timestamp DESC) as rn
            FROM messages
        ) m ON c.id = m.senderId AND m.rn = 1
        WHERE c.isBlocked = 0
        GROUP BY c.id
        ORDER BY COALESCE(m.timestamp, c.createdAt) DESC
        """
    )
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

    @Query("SELECT COUNT(*) FROM contacts WHERE isBlocked = 0")
    suspend fun getContactCount(): Int
}
