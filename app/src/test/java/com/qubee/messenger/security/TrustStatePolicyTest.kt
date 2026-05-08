package com.qubee.messenger.security

import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.TrustLevel
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustStatePolicyTest {

    @Test
    fun verifiedContactReceivingSameIdentityKeyRemainsVerified() {
        val key = byteArrayOf(1, 2, 3, 4)
        val contact = verifiedContact(identityKey = key)

        val updated = TrustStatePolicy.applyObservedIdentityKey(
            contact = contact,
            observedIdentityKey = key.copyOf(),
            nowMillis = 2_000L,
        )

        assertEquals(TrustLevel.VERIFIED, updated.trustLevel)
        assertEquals(ContactVerificationStatus.VERIFIED_ONCE, updated.verificationStatus)
        assertArrayEquals(key, updated.identityKey)
        assertTrue(TrustStatePolicy.canRenderAsVerified(updated))
        assertFalse(TrustStatePolicy.requiresKeyChangeWarning(updated))
    }

    @Test
    fun verifiedContactReceivingChangedIdentityKeyBecomesKeyChanged() {
        val oldKey = byteArrayOf(1, 2, 3, 4)
        val newKey = byteArrayOf(9, 8, 7, 6)
        val contact = verifiedContact(identityKey = oldKey)

        val updated = TrustStatePolicy.applyObservedIdentityKey(
            contact = contact,
            observedIdentityKey = newKey,
            nowMillis = 2_000L,
        )

        assertEquals(TrustLevel.KEY_CHANGED, updated.trustLevel)
        assertEquals(ContactVerificationStatus.UNVERIFIED, updated.verificationStatus)
        assertArrayEquals(newKey, updated.identityKey)
        assertEquals(2_000L, updated.updatedAt)
        assertFalse(TrustStatePolicy.canRenderAsVerified(updated))
        assertTrue(TrustStatePolicy.requiresKeyChangeWarning(updated))
    }

    @Test
    fun verifiedContactReceivingChangedPeerIdentityIdBecomesKeyChanged() {
        val contact = verifiedContact(identityKey = byteArrayOf(1, 2, 3, 4)).copy(
            identityId = "old-identity",
            peerId = "same-libp2p-peer",
        )

        val updated = TrustStatePolicy.applyObservedPeerIdentityId(
            contact = contact,
            observedIdentityId = "new-identity",
            nowMillis = 9_000L,
        )

        assertEquals(TrustLevel.KEY_CHANGED, updated.trustLevel)
        assertEquals(ContactVerificationStatus.UNVERIFIED, updated.verificationStatus)
        assertEquals("old-identity", updated.identityId)
        assertEquals("same-libp2p-peer", updated.peerId)
        assertEquals(9_000L, updated.updatedAt)
        assertFalse(TrustStatePolicy.canRenderAsVerified(updated))
        assertTrue(TrustStatePolicy.requiresKeyChangeWarning(updated))
    }

    @Test
    fun verifiedContactReceivingSamePeerIdentityIdRemainsVerified() {
        val contact = verifiedContact(identityKey = byteArrayOf(1, 2, 3, 4)).copy(
            identityId = "same-identity",
            peerId = "same-libp2p-peer",
        )

        val updated = TrustStatePolicy.applyObservedPeerIdentityId(
            contact = contact,
            observedIdentityId = "same-identity",
            nowMillis = 9_000L,
        )

        assertEquals(TrustLevel.VERIFIED, updated.trustLevel)
        assertEquals(ContactVerificationStatus.VERIFIED_ONCE, updated.verificationStatus)
        assertTrue(TrustStatePolicy.canRenderAsVerified(updated))
        assertFalse(TrustStatePolicy.requiresKeyChangeWarning(updated))
    }

    @Test
    fun keyChangedContactCannotSilentlyRenderAsVerifiedOrPqReady() {
        val contact = Contact(
            id = "bob",
            identityId = "bob-id",
            displayName = "Bob",
            identityKey = byteArrayOf(9, 8, 7, 6),
            trustLevel = TrustLevel.KEY_CHANGED,
            verificationStatus = ContactVerificationStatus.UNVERIFIED,
        )

        assertFalse(TrustStatePolicy.canRenderAsVerified(contact))
        assertTrue(TrustStatePolicy.requiresKeyChangeWarning(contact))
    }

    @Test
    fun nonVerifiedContactReceivingChangedIdentityKeyStaysUnverified() {
        val oldKey = byteArrayOf(1, 2, 3, 4)
        val newKey = byteArrayOf(4, 3, 2, 1)
        val contact = Contact(
            id = "bob",
            identityId = "bob-id",
            displayName = "Bob",
            identityKey = oldKey,
            trustLevel = TrustLevel.UNKNOWN,
            verificationStatus = ContactVerificationStatus.UNVERIFIED,
        )

        val updated = TrustStatePolicy.applyObservedIdentityKey(
            contact = contact,
            observedIdentityKey = newKey,
            nowMillis = 5_000L,
        )

        assertEquals(TrustLevel.UNKNOWN, updated.trustLevel)
        assertEquals(ContactVerificationStatus.UNVERIFIED, updated.verificationStatus)
        assertArrayEquals(newKey, updated.identityKey)
        assertFalse(TrustStatePolicy.canRenderAsVerified(updated))
    }

    @Test
    fun outOfBandVerificationOnUnknownContactBumpsToVerified() {
        val key = byteArrayOf(7, 8, 9, 10)
        val contact = Contact(
            id = "bob",
            identityId = "bob-id",
            displayName = "Bob",
            identityKey = null,
            trustLevel = TrustLevel.UNKNOWN,
            verificationStatus = ContactVerificationStatus.UNVERIFIED,
        )

        val updated = TrustStatePolicy.applyOutOfBandVerification(
            contact = contact,
            observedIdentityKey = key,
            nowMillis = 5_555L,
        )

        assertEquals(TrustLevel.VERIFIED, updated.trustLevel)
        assertEquals(ContactVerificationStatus.VERIFIED, updated.verificationStatus)
        assertArrayEquals(key, updated.identityKey)
        assertEquals(5_555L, updated.updatedAt)
        assertTrue(TrustStatePolicy.canRenderAsVerified(updated))
    }

    @Test
    fun outOfBandVerificationOnKeyChangedContactBumpsToVerifiedAndUpdatesKey() {
        val newKey = byteArrayOf(11, 22, 33)
        val contact = Contact(
            id = "carol",
            identityId = "carol-id",
            displayName = "Carol",
            identityKey = byteArrayOf(0, 0, 0, 0),
            trustLevel = TrustLevel.KEY_CHANGED,
            verificationStatus = ContactVerificationStatus.UNVERIFIED,
        )

        val updated = TrustStatePolicy.applyOutOfBandVerification(
            contact = contact,
            observedIdentityKey = newKey,
            nowMillis = 6_000L,
        )

        assertEquals(TrustLevel.VERIFIED, updated.trustLevel)
        assertEquals(ContactVerificationStatus.VERIFIED, updated.verificationStatus)
        assertArrayEquals(newKey, updated.identityKey)
        assertFalse(TrustStatePolicy.requiresKeyChangeWarning(updated))
    }

    @Test
    fun outOfBandVerificationCannotSilentlyClearCompromisedFlag() {
        val key = byteArrayOf(1, 2, 3)
        val contact = Contact(
            id = "dave",
            identityId = "dave-id",
            displayName = "Dave",
            identityKey = key,
            trustLevel = TrustLevel.COMPROMISED,
            verificationStatus = ContactVerificationStatus.UNVERIFIED,
        )

        val updated = TrustStatePolicy.applyOutOfBandVerification(
            contact = contact,
            observedIdentityKey = key,
            nowMillis = 7_000L,
        )

        // Identity-equal — caller can detect "policy declined" by
        // referential equality and refuse to write a no-op row.
        assertTrue(updated === contact)
        assertEquals(TrustLevel.COMPROMISED, updated.trustLevel)
        assertFalse(TrustStatePolicy.canRenderAsVerified(updated))
    }

    private fun verifiedContact(identityKey: ByteArray): Contact = Contact(
        id = "alice",
        identityId = "alice-id",
        displayName = "Alice",
        identityKey = identityKey,
        trustLevel = TrustLevel.VERIFIED,
        verificationStatus = ContactVerificationStatus.VERIFIED_ONCE,
        updatedAt = 1_000L,
    )
}
