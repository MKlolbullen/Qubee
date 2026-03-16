package com.qubee.messenger.state

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustStateMachineTest {
    @Test
    fun verifiedContactMovesToResetRequiredOnFingerprintChange() {
        val result = TrustStateMachine.reduce(
            current = TrustState.Verified,
            event = TrustEvent.PeerFingerprintObservedChanged,
        )

        assertEquals(TrustState.ResetRequired, result.state)
        assertTrue(result.sessionInvalidated)
        assertTrue(result.warningRequired)
    }

    @Test
    fun resetRequiredCanReturnToVerifiedAfterLocalVerification() {
        val result = TrustStateMachine.reduce(
            current = TrustState.ResetRequired,
            event = TrustEvent.LocalVerified,
        )

        assertEquals(TrustState.Verified, result.state)
        assertFalse(result.sessionInvalidated)
        assertFalse(result.warningRequired)
    }

    @Test
    fun blockedPeerReturnsToUnverifiedOnLocalReset() {
        val result = TrustStateMachine.reduce(
            current = TrustState.Blocked,
            event = TrustEvent.LocalReset,
        )

        assertEquals(TrustState.Unverified, result.state)
        assertTrue(result.sessionInvalidated)
        assertFalse(result.warningRequired)
    }

    @Test
    fun sameFingerprintObservationDoesNotDowngradeVerifiedTrust() {
        val result = TrustStateMachine.reduce(
            current = TrustState.Verified,
            event = TrustEvent.PeerFingerprintObservedSame,
        )

        assertEquals(TrustState.Verified, result.state)
        assertFalse(result.sessionInvalidated)
        assertFalse(result.warningRequired)
    }
}
