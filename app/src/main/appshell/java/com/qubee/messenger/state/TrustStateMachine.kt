package com.qubee.messenger.state

enum class TrustState {
    Unverified,
    Verified,
    ResetRequired,
    Blocked,
}

enum class TrustEvent {
    LocalVerified,
    LocalReset,
    PeerFingerprintObservedSame,
    PeerFingerprintObservedChanged,
    BlockPeer,
    AllowAfterReset,
}

data class TrustTransition(
    val state: TrustState,
    val sessionInvalidated: Boolean,
    val warningRequired: Boolean,
)

object TrustStateMachine {
    fun reduce(current: TrustState, event: TrustEvent): TrustTransition {
        return when (current) {
            TrustState.Unverified -> when (event) {
                TrustEvent.LocalVerified -> TrustTransition(TrustState.Verified, sessionInvalidated = false, warningRequired = false)
                TrustEvent.BlockPeer -> TrustTransition(TrustState.Blocked, sessionInvalidated = true, warningRequired = false)
                TrustEvent.PeerFingerprintObservedChanged -> TrustTransition(TrustState.ResetRequired, sessionInvalidated = true, warningRequired = true)
                else -> TrustTransition(current, sessionInvalidated = false, warningRequired = false)
            }

            TrustState.Verified -> when (event) {
                TrustEvent.PeerFingerprintObservedSame -> TrustTransition(TrustState.Verified, sessionInvalidated = false, warningRequired = false)
                TrustEvent.PeerFingerprintObservedChanged -> TrustTransition(TrustState.ResetRequired, sessionInvalidated = true, warningRequired = true)
                TrustEvent.BlockPeer -> TrustTransition(TrustState.Blocked, sessionInvalidated = true, warningRequired = false)
                TrustEvent.LocalReset -> TrustTransition(TrustState.Unverified, sessionInvalidated = true, warningRequired = false)
                else -> TrustTransition(current, sessionInvalidated = false, warningRequired = false)
            }

            TrustState.ResetRequired -> when (event) {
                TrustEvent.LocalVerified,
                TrustEvent.AllowAfterReset,
                -> TrustTransition(TrustState.Verified, sessionInvalidated = false, warningRequired = false)

                TrustEvent.BlockPeer -> TrustTransition(TrustState.Blocked, sessionInvalidated = true, warningRequired = false)
                TrustEvent.LocalReset -> TrustTransition(TrustState.Unverified, sessionInvalidated = true, warningRequired = false)
                else -> TrustTransition(current, sessionInvalidated = false, warningRequired = true)
            }

            TrustState.Blocked -> when (event) {
                TrustEvent.LocalReset -> TrustTransition(TrustState.Unverified, sessionInvalidated = true, warningRequired = false)
                else -> TrustTransition(current, sessionInvalidated = false, warningRequired = false)
            }
        }
    }
}
