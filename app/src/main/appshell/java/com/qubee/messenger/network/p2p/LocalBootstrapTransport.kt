package com.qubee.messenger.network.p2p

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class LocalBootstrapStatus(
    val ready: Boolean = false,
    val details: String = "Local bootstrap idle.",
    val peerHintCount: Int = 0,
)

class LocalBootstrapTransport(
    context: Context,
) : SignalingTransport, BootstrapRegistrationSink {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val wifiDirect = WifiDirectBootstrapTransport(context)
    private val ble = BleBootstrapTransport(context)
    private val fanIn = MutableSharedFlow<SignalingMessage>(extraBufferCapacity = 128)
    private var wifiCollectorJob: Job? = null
    private var bleCollectorJob: Job? = null
    private var started = false
    private val mutableStatus = MutableStateFlow(LocalBootstrapStatus())

    val status: StateFlow<LocalBootstrapStatus> = mutableStatus.asStateFlow()

    override val transportName: String = "local-bootstrap-mux"

    override suspend fun start(localHandle: String) {
        if (started) return
        started = true
        wifiDirect.start(localHandle)
        ble.start(localHandle)
        pushStatus("Local bootstrap online.")
        wifiCollectorJob = scope.launch { wifiDirect.incoming().collect { fanIn.emit(it) } }
        bleCollectorJob = scope.launch { ble.incoming().collect { fanIn.emit(it) } }
    }

    override suspend fun stop() {
        started = false
        wifiCollectorJob?.cancelAndJoin()
        bleCollectorJob?.cancelAndJoin()
        wifiCollectorJob = null
        bleCollectorJob = null
        wifiDirect.stop()
        ble.stop()
        pushStatus("Local bootstrap stopped.")
    }

    override suspend fun publish(message: SignalingMessage) {
        wifiDirect.publish(message)
        ble.publish(message)
        pushStatus("Dispatching local signaling for ${message.peerHandle}.")
    }

    override fun incoming(): Flow<SignalingMessage> = fanIn.asSharedFlow()

    override fun updateLocalBootstrapIdentity(localBootstrapToken: String, localDeviceId: String) {
        wifiDirect.updateLocalBootstrapIdentity(localBootstrapToken, localDeviceId)
        ble.updateLocalBootstrapIdentity(localBootstrapToken, localDeviceId)
        pushStatus("Local bootstrap identity configured.")
    }

    override fun registerPeerBootstrap(hint: BootstrapPeerHint) {
        wifiDirect.registerPeerBootstrap(hint)
        ble.registerPeerBootstrap(hint)
        pushStatus("Registered peer bootstrap hints.")
    }


    private fun pushStatus(details: String) {
        mutableStatus.value = LocalBootstrapStatus(
            ready = started,
            details = details,
            peerHintCount = if (started) 1 else 0,
        )
    }
}
