package com.qubee.messenger.state

sealed interface VaultFlowState {
    data object Locked : VaultFlowState
    data object Unlocking : VaultFlowState
    data object Unlocked : VaultFlowState
    data class Error(val reason: String) : VaultFlowState
}

sealed interface BootstrapFlowState {
    data object Idle : BootstrapFlowState
    data object ExportingInvite : BootstrapFlowState
    data object ImportingInvite : BootstrapFlowState
    data object AwaitingVerification : BootstrapFlowState
    data object Verified : BootstrapFlowState
    data class Error(val reason: String) : BootstrapFlowState
}

sealed interface TransportFlowState {
    data object Idle : TransportFlowState
    data object Bootstrapping : TransportFlowState
    data object ConnectingRtc : TransportFlowState
    data object RtcReady : TransportFlowState
    data object RelayFallback : TransportFlowState
    data object Rehydrating : TransportFlowState
    data class Error(val reason: String) : TransportFlowState
}

sealed interface OutboundQueueState {
    data object Empty : OutboundQueueState
    data class Pending(val count: Int) : OutboundQueueState
    data object Sending : OutboundQueueState
    data object Replaying : OutboundQueueState
    data class Failed(val reason: String) : OutboundQueueState
}
