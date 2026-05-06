package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.ContactWithLastMessage
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.database.dao.ContactDao
import com.qubee.messenger.data.repository.database.dao.CryptoKeyDao
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.security.TrustStatePolicy
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

// Real Room-backed implementation. Crypto-backed surfaces
// (addContactFromInviteLink, verifyIdentityKey, generateSAS) route
// through QubeeManager's JNI bridge; private key material never
// leaves Rust.
@Singleton
class ContactRepository @Inject constructor(
    private val contactDao: ContactDao,
    @Suppress("unused") private val cryptoKeyDao: CryptoKeyDao,
    private val qubeeManager: QubeeManager,
) {

    fun getAllContactsFlow(): Flow<List<Contact>> = contactDao.getAllContacts()

    fun getContactFlow(contactId: String): Flow<Contact?> =
        contactDao.getContactFlow(contactId)

    fun getContactsWithLastMessage(): Flow<List<ContactWithLastMessage>> =
        contactDao.getContactsWithLastMessage()

    suspend fun getAllContacts(): List<Contact> = contactDao.getAllContacts().first()

    suspend fun getContactById(contactId: String): Contact? =
        contactDao.getContactById(contactId)

    suspend fun getContactByIdentityId(identityId: String): Contact? =
        contactDao.getContactByIdentityId(identityId)

    /// Look up a contact by their libp2p PeerId. Returns null if no
    /// contact has been linked to this PeerId yet — populated by
    /// `MessageService.onMessageReceived` on first inbound from a
    /// known identity (via `inspectEnvelopeSender`). Callers should
    /// fall back gracefully on null.
    suspend fun getContactByPeerId(peerId: String): Contact? =
        contactDao.getContactByPeerId(peerId)

    suspend fun updatePeerId(contactId: String, peerId: String?) {
        contactDao.updatePeerId(contactId, peerId)
    }

    /**
     * Persist an observed contact identity key through the trust-state policy.
     *
     * This is the choke point for key-change safety: callers that learn a peer identity from
     * onboarding, peer-link inspection, inbound message sender inspection, or future sync flows
     * should call this instead of directly overwriting Contact.identityKey. A previously verified
     * contact presenting a different key is downgraded to TrustLevel.KEY_CHANGED and must not render
     * as verified until re-verification succeeds.
     */
    suspend fun observeIdentityKey(contactId: String, observedIdentityKey: ByteArray?, nowMillis: Long = System.currentTimeMillis()): Contact? {
        val existing = contactDao.getContactById(contactId) ?: return null
        val updated = TrustStatePolicy.applyObservedIdentityKey(
            contact = existing,
            observedIdentityKey = observedIdentityKey,
            nowMillis = nowMillis,
        )
        if (updated != existing) {
            contactDao.updateContact(updated)
        }
        return updated
    }

    /**
     * Link a libp2p peer id to an observed Qubee identity id without bypassing trust policy.
     *
     * This handles two cases:
     * - Known identityId: stamp/update Contact.peerId.
     * - Existing peerId linked to a different identityId: downgrade that contact to KEY_CHANGED
     *   before any UI can keep rendering it as verified.
     */
    suspend fun observePeerIdentityLink(peerId: String, identityIdHex: String, nowMillis: Long = System.currentTimeMillis()): Contact? {
        val byPeer = contactDao.getContactByPeerId(peerId)
        if (byPeer != null && byPeer.identityId != identityIdHex) {
            val downgraded = TrustStatePolicy.applyObservedPeerIdentityId(
                contact = byPeer,
                observedIdentityId = identityIdHex,
                nowMillis = nowMillis,
            )
            if (downgraded != byPeer) {
                contactDao.updateContact(downgraded)
            }
            return downgraded
        }

        val byIdentity = contactDao.getContactByIdentityId(identityIdHex) ?: return byPeer
        if (byIdentity.peerId == peerId) return byIdentity

        val updated = byIdentity.copy(peerId = peerId, updatedAt = nowMillis)
        contactDao.updateContact(updated)
        return updated
    }

    suspend fun getContactName(contactId: String): String =
        contactDao.getContactById(contactId)?.displayName ?: ""

    suspend fun searchContacts(query: String): List<Contact> =
        contactDao.searchContacts(query)

    suspend fun getContactsByTrustLevel(level: TrustLevel): List<Contact> =
        contactDao.getContactsByTrustLevel(level)

    suspend fun blockContact(contactId: String) {
        contactDao.updateBlockedStatus(contactId, true)
    }

    /// Counterpart to [blockContact] — flips `Contact.isBlocked` back
    /// to `false`. The contact reappears on the active address-book
    /// list and inbound from them stops being suppressed.
    suspend fun unblockContact(contactId: String) {
        contactDao.updateBlockedStatus(contactId, false)
    }

    /// Stream of contacts the local user has blocked. Surfaced on
    /// the Contacts tab as a separate "Blocked" section so the user
    /// can unblock without spelunking through Settings.
    fun getBlockedContactsFlow(): kotlinx.coroutines.flow.Flow<List<Contact>> =
        contactDao.getBlockedContacts()

    suspend fun deleteContact(contactId: String) {
        contactDao.deleteContactById(contactId)
    }

    suspend fun updateProfilePicture(contactId: String, url: String?) {
        contactDao.updateProfilePicture(contactId, url)
    }

    suspend fun updateTrustLevel(contactId: String, level: TrustLevel) {
        contactDao.updateTrustLevel(contactId, level)
    }

    suspend fun updateVerificationStatus(contactId: String, status: ContactVerificationStatus) {
        contactDao.updateVerificationStatus(contactId, status)
    }

    suspend fun updateOnlineStatus(contactId: String, online: Boolean, lastSeen: Long?) {
        contactDao.updateOnlineStatus(contactId, online, lastSeen)
    }

    suspend fun upsertContact(contact: Contact) {
        contactDao.insertContact(contact)
    }

    // ---- Crypto-backed surfaces -----------------------------------

    /**
     * Verify a `qubee://identity/...` share link's hybrid signature
     * via the Rust core, decode the resulting identity bundle, and
     * persist it as a new (or updated) contact. Returns the upserted
     * `Contact` on success, or `null` if the link is malformed,
     * tampered, or the JNI surface is unavailable.
     *
     * The first-time observation goes through `TrustStatePolicy` to
     * establish a non-verified trust baseline; the user must complete
     * the OOB ceremony separately to bump to `TrustLevel.VERIFIED`.
     */
    suspend fun addContactFromInviteLink(link: String): Contact? {
        val json = qubeeManager.verifyOnboardingLink(link) ?: return null
        val bundle = IdentityBundle.fromJson(json) ?: return null

        val now = System.currentTimeMillis()
        val identityKey = runCatching { hexToBytes(bundle.identityIdHex) }.getOrNull()
        val existing = contactDao.getContactByIdentityId(bundle.identityIdHex)

        val contact = if (existing != null) {
            existing.copy(
                displayName = bundle.displayName.ifBlank { existing.displayName },
                identityKey = identityKey ?: existing.identityKey,
                updatedAt = now,
            )
        } else {
            Contact(
                id = UUID.randomUUID().toString(),
                identityId = bundle.identityIdHex,
                displayName = bundle.displayName,
                identityKey = identityKey,
                trustLevel = TrustLevel.UNKNOWN,
                verificationStatus = ContactVerificationStatus.UNVERIFIED,
                createdAt = now,
                updatedAt = now,
            )
        }
        contactDao.insertContact(contact)
        return contact
    }

    /**
     * Verify a peer's `IdentityKey` against a verification payload via
     * the Rust core's hybrid Ed25519 + ML-DSA-44 check. On success,
     * stamp the contact's trust state through `TrustStatePolicy`
     * (which is the choke point that downgrades a previously-verified
     * contact whose key changed).
     */
    suspend fun verifyIdentityKey(
        contactId: String,
        key: ByteArray,
        verificationData: ByteArray = ByteArray(0),
    ): Boolean {
        val ok = qubeeManager.verifyIdentityKey(contactId, key, verificationData)
        if (!ok) return false
        val existing = contactDao.getContactById(contactId) ?: return false
        val now = System.currentTimeMillis()
        val withKey = TrustStatePolicy.applyObservedIdentityKey(
            contact = existing,
            observedIdentityKey = key,
            nowMillis = now,
        )
        val verified = withKey.copy(
            trustLevel = TrustLevel.VERIFIED,
            verificationStatus = ContactVerificationStatus.VERIFIED,
            updatedAt = now,
        )
        contactDao.updateContact(verified)
        return true
    }

    /**
     * Compute the Short Authentication String for a contact by routing
     * their stored `identityKey` through `QubeeManager.generateSASForContact`.
     * Returns the empty string when the contact is unknown, has no
     * stored identity key, or the JNI call fails.
     */
    suspend fun generateSAS(contactId: String): String {
        val contact = contactDao.getContactById(contactId) ?: return ""
        val peerKey = contact.identityKey ?: return ""
        return qubeeManager.generateSASForContact(peerKey).orEmpty()
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "odd-length hex: ${hex.length}" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[2 * i], 16)
            val lo = Character.digit(hex[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "non-hex char at index ${2 * i}" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
