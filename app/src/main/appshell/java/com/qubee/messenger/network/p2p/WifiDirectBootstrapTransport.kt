package com.qubee.messenger.network.p2p

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.NetworkInfo
import android.net.wifi.WpsInfo
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pDeviceList
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

@SuppressLint("MissingPermission")
class WifiDirectBootstrapTransport(
    private val appContext: Context,
) : SignalingTransport, BootstrapRegistrationSink {
    override val transportName: String = "wifi-direct-bootstrap"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val incomingBus = MutableSharedFlow<SignalingMessage>(extraBufferCapacity = 128)
    private val peerHints = ConcurrentHashMap<String, BootstrapPeerHint>()
    private val discoveredPeers = ConcurrentHashMap<String, WifiP2pDevice>()
    private val peerSockets = ConcurrentHashMap<String, SocketPeerEndpoint>()
    private val tokenHashToHandle = ConcurrentHashMap<String, String>()
    private val connectionAttempts = ConcurrentHashMap.newKeySet<String>()

    private var localHandle: String = ""
    private var localBootstrapToken: String = ""
    private var localTokenHash: String = ""
    private var localDeviceId: String = ""
    private var started = false
    private var receiverRegistered = false
    private var groupFormed = false
    private var isGroupOwner = false
    private var groupOwnerHost: String? = null
    private var serverSocket: ServerSocket? = null
    private val signalPort = 42672

    private val wifiManager: WifiP2pManager? = appContext.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    private val wifiChannel: WifiP2pManager.Channel? = wifiManager?.initialize(appContext, appContext.mainLooper, null)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> requestPeers()
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> handleConnectionChanged(intent)
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val enabled = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, WifiP2pManager.WIFI_P2P_STATE_DISABLED) == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                    if (enabled) discoverPeers()
                }
            }
        }
    }

    override suspend fun start(localHandle: String) {
        if (started) return
        started = true
        this.localHandle = localHandle
        startServerSocket()
        registerReceiverIfNeeded()
        discoverPeers()
    }

    override suspend fun stop() {
        started = false
        unregisterReceiverIfNeeded()
        serverSocket?.close()
        serverSocket = null
        peerSockets.values.forEach { it.close() }
        peerSockets.clear()
        discoveredPeers.clear()
        connectionAttempts.clear()
        groupFormed = false
        isGroupOwner = false
        groupOwnerHost = null
    }

    override suspend fun publish(message: SignalingMessage) {
        peerSockets[message.peerHandle]?.takeIf { it.isOpen() }?.send(BootstrapWireFrame.Signal(message))?.let { return }
        ensureConnectivityFor(message.peerHandle)
        peerSockets[message.peerHandle]?.takeIf { it.isOpen() }?.send(BootstrapWireFrame.Signal(message))
    }

    override fun incoming(): Flow<SignalingMessage> = incomingBus.asSharedFlow()

    override fun updateLocalBootstrapIdentity(localBootstrapToken: String, localDeviceId: String) {
        this.localBootstrapToken = localBootstrapToken
        this.localTokenHash = BootstrapTokenHasher.hash(localBootstrapToken)
        this.localDeviceId = localDeviceId
    }

    override fun registerPeerBootstrap(hint: BootstrapPeerHint) {
        peerHints[hint.peerHandle] = hint
        tokenHashToHandle[BootstrapTokenHasher.hash(hint.peerBootstrapToken)] = hint.peerHandle
        ensureConnectivityFor(hint.peerHandle)
    }

    private fun ensureConnectivityFor(peerHandle: String) {
        if (!started || !hasWifiDirectPermission()) return
        if (peerSockets[peerHandle]?.isOpen() == true) return
        val ownerHost = groupOwnerHost
        if (groupFormed && !isGroupOwner && !ownerHost.isNullOrBlank()) {
            scope.launch { connectToEndpoint(ownerHost, peerHandle) }
            return
        }
        maybeConnectToDiscoveredPeer(peerHandle)
        if (discoveredPeers.isEmpty()) discoverPeers()
    }

    private fun discoverPeers() {
        if (!hasWifiDirectPermission()) return
        wifiManager?.discoverPeers(wifiChannel, null)
    }

    private fun requestPeers() {
        if (!hasWifiDirectPermission()) return
        wifiManager?.requestPeers(wifiChannel) { peers: WifiP2pDeviceList ->
            discoveredPeers.clear()
            peers.deviceList.forEach { device -> discoveredPeers[device.deviceAddress] = device }
            peerHints.keys.forEach(::maybeConnectToDiscoveredPeer)
        }
    }

    private fun handleConnectionChanged(intent: Intent) {
        val networkInfo = intent.getParcelableExtra<NetworkInfo>(WifiP2pManager.EXTRA_NETWORK_INFO)
        if (networkInfo?.isConnected != true) {
            groupFormed = false
            isGroupOwner = false
            groupOwnerHost = null
            return
        }
        wifiManager?.requestConnectionInfo(wifiChannel) { info: WifiP2pInfo ->
            groupFormed = info.groupFormed
            isGroupOwner = info.isGroupOwner
            groupOwnerHost = info.groupOwnerAddress?.hostAddress
            if (info.groupFormed && !info.isGroupOwner) {
                val preferredPeer = peerHints.keys.firstOrNull()
                val host = info.groupOwnerAddress?.hostAddress
                if (!host.isNullOrBlank() && preferredPeer != null) {
                    scope.launch { connectToEndpoint(host, preferredPeer) }
                }
            }
        }
    }

    private fun maybeConnectToDiscoveredPeer(peerHandle: String) {
        if (!hasWifiDirectPermission()) return
        val hint = peerHints[peerHandle] ?: return
        if (hint.preference == BootstrapTransportPreference.BleOnly || !connectionAttempts.add(peerHandle)) return
        val candidate = discoveredPeers.values.firstOrNull() ?: return
        val config = WifiP2pConfig().apply {
            deviceAddress = candidate.deviceAddress
            wps.setup = WpsInfo.PBC
        }
        wifiManager?.connect(wifiChannel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() = Unit
            override fun onFailure(reason: Int) { connectionAttempts.remove(peerHandle) }
        })
    }

    private fun startServerSocket() {
        if (serverSocket != null) return
        serverSocket = ServerSocket(signalPort)
        scope.launch {
            while (started) {
                val socket = runCatching { serverSocket?.accept() }.getOrNull() ?: break
                registerSocket(socket, outboundPeerHandle = null)
            }
        }
    }

    private suspend fun connectToEndpoint(host: String, peerHandle: String) {
        if (peerSockets[peerHandle]?.isOpen() == true) return
        runCatching {
            Socket(InetAddress.getByName(host), signalPort).also { socket ->
                registerSocket(socket, outboundPeerHandle = peerHandle)
            }
        }
    }

    private fun registerSocket(socket: Socket, outboundPeerHandle: String?) {
        scope.launch {
            val endpoint = SocketPeerEndpoint(
                socket = socket,
                reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8)),
                writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8)),
            )
            if (outboundPeerHandle != null) {
                endpoint.send(
                    BootstrapWireFrame.Hello(
                        targetToken = peerHints[outboundPeerHandle]?.peerBootstrapToken.orEmpty(),
                        fromHandle = localHandle,
                        fromDeviceId = localDeviceId,
                        fromTokenHash = localTokenHash,
                        transport = transportName,
                    )
                )
            }
            try {
                while (started && endpoint.isOpen()) {
                    val line = endpoint.reader.readLine() ?: break
                    handleWireFrame(endpoint, BootstrapWireCodec.decode(line))
                }
            } finally {
                endpoint.remoteHandle?.let { handle ->
                    if (peerSockets[handle] === endpoint) peerSockets.remove(handle)
                }
                endpoint.close()
            }
        }
    }

    private suspend fun handleWireFrame(endpoint: SocketPeerEndpoint, frame: BootstrapWireFrame) {
        when (frame) {
            is BootstrapWireFrame.Hello -> {
                if (localBootstrapToken.isNotBlank() && frame.targetToken.isNotBlank() && frame.targetToken != localBootstrapToken) return
                endpoint.remoteHandle = frame.fromHandle
                endpoint.remoteDeviceId = frame.fromDeviceId
                peerSockets[frame.fromHandle] = endpoint
                tokenHashToHandle[frame.fromTokenHash] = frame.fromHandle
                endpoint.send(
                    BootstrapWireFrame.HelloAck(
                        fromHandle = localHandle,
                        fromDeviceId = localDeviceId,
                        fromTokenHash = localTokenHash,
                        transport = transportName,
                    )
                )
            }
            is BootstrapWireFrame.HelloAck -> {
                endpoint.remoteHandle = frame.fromHandle
                endpoint.remoteDeviceId = frame.fromDeviceId
                peerSockets[frame.fromHandle] = endpoint
                tokenHashToHandle[frame.fromTokenHash] = frame.fromHandle
            }
            is BootstrapWireFrame.Signal -> {
                if (frame.message.peerHandle == localHandle) incomingBus.emit(frame.message)
            }
        }
    }

    private fun registerReceiverIfNeeded() {
        if (receiverRegistered) return
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            appContext.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            appContext.registerReceiver(receiver, filter)
        }
        receiverRegistered = true
    }

    private fun unregisterReceiverIfNeeded() {
        if (!receiverRegistered) return
        runCatching { appContext.unregisterReceiver(receiver) }
        receiverRegistered = false
    }

    private fun hasWifiDirectPermission(): Boolean = when {
        Build.VERSION.SDK_INT >= 33 -> ContextCompat.checkSelfPermission(appContext, Manifest.permission.NEARBY_WIFI_DEVICES) == PackageManager.PERMISSION_GRANTED
        else -> ContextCompat.checkSelfPermission(appContext, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
    }

    private data class SocketPeerEndpoint(
        val socket: Socket,
        val reader: BufferedReader,
        val writer: BufferedWriter,
        var remoteHandle: String? = null,
        var remoteDeviceId: String = "",
    ) {
        fun isOpen(): Boolean = socket.isConnected && !socket.isClosed

        fun send(frame: BootstrapWireFrame) {
            writer.write(BootstrapWireCodec.encodeLine(frame))
            writer.flush()
        }

        fun close() {
            runCatching { socket.close() }
        }
    }
}
