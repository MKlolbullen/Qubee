package com.qubee.messenger.network.p2p

interface BootstrapRegistrationSink {
    fun updateLocalBootstrapIdentity(localBootstrapToken: String, localDeviceId: String)
    fun registerPeerBootstrap(hint: BootstrapPeerHint)
}
