package com.qubee.messenger.security

import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.TrustLevel

/**
 * Pure trust-state transition policy for contact identity updates.
 *
 * This intentionally contains no Android, Room, JNI or coroutine dependencies so it can be
 * unit-tested cheaply. Repositories/services should call this before persisting contact identity
 * changes, and UI should derive security presentation from the resulting Contact state.
 */
object TrustStatePolicy {

    /**
     * Apply an observed identity key to an existing contact.
     *
     * Rules:
     * - Same key: preserve trust state exactly.
     * - First key: store it without granting verification.
     * - Changed key on VERIFIED contact: downgrade to KEY_CHANGED and UNVERIFIED.
     * - Changed key on non-verified contact: keep it unverified and update the stored key.
     * - COMPROMISED/BLOCKED-equivalent states should not be upgraded by key observation.
     */
    fun applyObservedIdentityKey(
        contact: Contact,
        observedIdentityKey: ByteArray?,
        nowMillis: Long,
    ): Contact {
        if (observedIdentityKey == null || observedIdentityKey.isEmpty()) return contact

        val previous = contact.identityKey
        if (previous != null && previous.contentEquals(observedIdentityKey)) {
            return contact
        }

        val changedExistingKey = previous != null && !previous.contentEquals(observedIdentityKey)

        val nextTrust = when {
            !changedExistingKey -> contact.trustLevel
            contact.trustLevel == TrustLevel.VERIFIED -> TrustLevel.KEY_CHANGED
            contact.trustLevel == TrustLevel.COMPROMISED -> TrustLevel.COMPROMISED
            else -> TrustLevel.UNKNOWN
        }

        val nextVerification = when {
            changedExistingKey && contact.trustLevel == TrustLevel.VERIFIED ->
                ContactVerificationStatus.UNVERIFIED
            changedExistingKey && contact.verificationStatus != ContactVerificationStatus.UNVERIFIED ->
                ContactVerificationStatus.UNVERIFIED
            else -> contact.verificationStatus
        }

        return contact.copy(
            identityKey = observedIdentityKey.copyOf(),
            trustLevel = nextTrust,
            verificationStatus = nextVerification,
            updatedAt = nowMillis,
        )
    }

    /**
     * Apply a Qubee identityId observation from the transport/handshake layer.
     *
     * This catches a high-risk edge case: the same libp2p PeerId is now linked to a different Qubee
     * identityId than the contact row previously held. The callback may not have raw public key
     * bytes yet, but an identityId mismatch is enough to downgrade trust and force re-verification.
     */
    fun applyObservedPeerIdentityId(
        contact: Contact,
        observedIdentityId: String,
        nowMillis: Long,
    ): Contact {
        if (observedIdentityId.isBlank() || observedIdentityId == contact.identityId) return contact

        val nextTrust = when (contact.trustLevel) {
            TrustLevel.VERIFIED -> TrustLevel.KEY_CHANGED
            TrustLevel.COMPROMISED -> TrustLevel.COMPROMISED
            else -> TrustLevel.UNKNOWN
        }

        return contact.copy(
            trustLevel = nextTrust,
            verificationStatus = ContactVerificationStatus.UNVERIFIED,
            updatedAt = nowMillis,
        )
    }

    /**
     * Whether this contact is allowed to render as high-trust / verified in chat UI.
     */
    fun canRenderAsVerified(contact: Contact?): Boolean =
        contact?.trustLevel == TrustLevel.VERIFIED &&
            contact.verificationStatus != ContactVerificationStatus.UNVERIFIED

    /**
     * Whether the user must be shown a key-change warning before trusting this contact again.
     */
    fun requiresKeyChangeWarning(contact: Contact?): Boolean =
        contact?.trustLevel == TrustLevel.KEY_CHANGED
}
