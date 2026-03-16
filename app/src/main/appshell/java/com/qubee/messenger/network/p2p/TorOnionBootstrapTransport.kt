package com.qubee.messenger.network.p2p

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.filter

class TorOnionBootstrapTransport : SignalingTransport, BootstrapRegistrationSink {
    private var localHandle: String = ""
    override val transportName: String = "tor-onion-bootstrap"

    override suspend fun start(localHandle: String) {
        this.localHandle = localHandle
    }

    override suspend fun stop() = Unit

    override suspend fun publish(message: SignalingMessage) {
        onionBus.emit(message)
    }

    override fun incoming(): Flow<SignalingMessage> = onionBus.asSharedFlow().filter { it.peerHandle == localHandle }

    override fun updateLocalBootstrapIdentity(localBootstrapToken: String, localDeviceId: String) = Unit

    override fun registerPeerBootstrap(hint: BootstrapPeerHint) = Unit

    private companion object {
        val onionBus = MutableSharedFlow<SignalingMessage>(extraBufferCapacity = 128)
    }
}
