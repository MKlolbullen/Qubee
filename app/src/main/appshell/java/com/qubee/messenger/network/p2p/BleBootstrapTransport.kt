package com.qubee.messenger.network.p2p

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

@SuppressLint("MissingPermission")
class BleBootstrapTransport(
    private val appContext: Context,
) : SignalingTransport, BootstrapRegistrationSink {
    override val transportName: String = "ble-bootstrap"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val incomingBus = MutableSharedFlow<SignalingMessage>(extraBufferCapacity = 128)
    private val peerHints = ConcurrentHashMap<String, BootstrapPeerHint>()
    private val tokenPrefixToHandle = ConcurrentHashMap<String, String>()
    private val peerSessions = ConcurrentHashMap<String, BlePeerSession>()
    private val addressToSession = ConcurrentHashMap<String, BlePeerSession>()
    private val connectingAddresses = ConcurrentHashMap.newKeySet<String>()

    private var localHandle: String = ""
    private var localDeviceId: String = ""
    private var localBootstrapToken: String = ""
    private var localTokenPrefix: String = ""
    private var started = false

    private val bluetoothManager: BluetoothManager? = appContext.getSystemService(BluetoothManager::class.java)
    private val bluetoothAdapter: BluetoothAdapter? get() = bluetoothManager?.adapter
    private val advertiser: BluetoothLeAdvertiser? get() = bluetoothAdapter?.bluetoothLeAdvertiser
    private val scanner: BluetoothLeScanner? get() = bluetoothAdapter?.bluetoothLeScanner

    private var gattServer: BluetoothGattServer? = null
    private var l2capServerSocket: BluetoothServerSocket? = null
    private var l2capPsm: Int = -1

    override suspend fun start(localHandle: String) {
        if (started) return
        started = true
        this.localHandle = localHandle
        if (!hasBlePermissions() || bluetoothAdapter?.isEnabled != true) return
        startGattServer()
        startL2capServer()
        startAdvertising()
        startScanning()
    }

    override suspend fun stop() {
        started = false
        runCatching { scanner?.stopScan(scanCallback) }
        runCatching { advertiser?.stopAdvertising(advertiseCallback) }
        peerSessions.values.forEach { it.close() }
        peerSessions.clear()
        addressToSession.clear()
        connectingAddresses.clear()
        runCatching { gattServer?.close() }
        gattServer = null
        runCatching { l2capServerSocket?.close() }
        l2capServerSocket = null
    }

    override suspend fun publish(message: SignalingMessage) {
        val session = peerSessions[message.peerHandle]
        if (session?.sendViaL2cap(BootstrapWireFrame.Signal(message)) == true) return
        if (session?.sendViaGatt(BootstrapWireFrame.Signal(message)) == true) return
        peerHints[message.peerHandle]?.let { maybeConnectToHint(it) }
    }

    override fun incoming(): Flow<SignalingMessage> = incomingBus.asSharedFlow()

    override fun updateLocalBootstrapIdentity(localBootstrapToken: String, localDeviceId: String) {
        this.localBootstrapToken = localBootstrapToken
        this.localDeviceId = localDeviceId
        this.localTokenPrefix = BootstrapTokenHasher.hintPrefix(localBootstrapToken)
    }

    override fun registerPeerBootstrap(hint: BootstrapPeerHint) {
        peerHints[hint.peerHandle] = hint
        tokenPrefixToHandle[BootstrapTokenHasher.hintPrefix(hint.peerBootstrapToken)] = hint.peerHandle
        maybeConnectToHint(hint)
    }

    private fun maybeConnectToHint(hint: BootstrapPeerHint) {
        if (!started || hint.preference == BootstrapTransportPreference.WifiDirectOnly) return
        startScanning()
    }

    private fun startGattServer() {
        if (gattServer != null) return
        gattServer = bluetoothManager?.openGattServer(appContext, serverCallback)
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                METADATA_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ,
            )
        )
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                UPLINK_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            )
        )
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                DOWNLINK_UUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ,
            ).apply {
                addDescriptor(
                    BluetoothGattDescriptor(
                        CCCD_UUID,
                        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
                    )
                )
            }
        )
        gattServer?.addService(service)
    }

    private fun startAdvertising() {
        if (!hasBlePermissions()) return
        val serviceData = localTokenPrefix.toByteArray(Charsets.UTF_8)
        advertiser?.startAdvertising(
            AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .build(),
            AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(ParcelUuid(SERVICE_UUID))
                .addServiceData(ParcelUuid(SERVICE_UUID), serviceData)
                .build(),
            advertiseCallback,
        )
    }

    private fun startScanning() {
        if (!hasBlePermissions()) return
        scanner?.stopScan(scanCallback)
        scanner?.startScan(
            listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()),
            ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
            scanCallback,
        )
    }

    private fun startL2capServer() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || l2capServerSocket != null || !hasBlePermissions()) return
        val server = runCatching { bluetoothAdapter?.listenUsingInsecureL2capChannel() }.getOrNull() ?: return
        l2capServerSocket = server
        l2capPsm = runCatching { server.psm }.getOrElse { -1 }
        scope.launch {
            while (started) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                registerL2capSocket(socket, hintedHandle = null)
            }
        }
    }

    private fun registerL2capSocket(socket: BluetoothSocket, hintedHandle: String?) {
        scope.launch {
            val session = if (hintedHandle != null) {
                peerSessions[hintedHandle] ?: BlePeerSession(device = socket.remoteDevice, peerHandle = hintedHandle).also {
                    peerSessions[hintedHandle] = it
                    addressToSession[socket.remoteDevice.address] = it
                }
            } else {
                addressToSession[socket.remoteDevice.address] ?: BlePeerSession(device = socket.remoteDevice).also {
                    addressToSession[socket.remoteDevice.address] = it
                }
            }
            session.attachL2cap(socket)
            if (!hintedHandle.isNullOrBlank()) {
                session.sendViaL2cap(
                    BootstrapWireFrame.Hello(
                        targetToken = peerHints[hintedHandle]?.peerBootstrapToken.orEmpty(),
                        fromHandle = localHandle,
                        fromDeviceId = localDeviceId,
                        fromTokenHash = localTokenPrefix,
                        transport = transportName,
                    )
                )
            }
            try {
                while (started && session.isL2capOpen()) {
                    val line = session.l2capReader?.readLine() ?: break
                    handleWireFrame(session, BootstrapWireCodec.decode(line))
                }
            } finally {
                session.detachL2cap()
            }
        }
    }

    private suspend fun handleWireFrame(session: BlePeerSession, frame: BootstrapWireFrame) {
        when (frame) {
            is BootstrapWireFrame.Hello -> {
                if (localBootstrapToken.isNotBlank() && frame.targetToken.isNotBlank() && frame.targetToken != localBootstrapToken) return
                session.peerHandle = frame.fromHandle
                session.remoteTokenPrefix = frame.fromTokenHash
                peerSessions[frame.fromHandle] = session
                addressToSession[session.device.address] = session
                session.sendViaL2cap(
                    BootstrapWireFrame.HelloAck(
                        fromHandle = localHandle,
                        fromDeviceId = localDeviceId,
                        fromTokenHash = localTokenPrefix,
                        transport = transportName,
                    )
                )
                session.sendViaGatt(
                    BootstrapWireFrame.HelloAck(
                        fromHandle = localHandle,
                        fromDeviceId = localDeviceId,
                        fromTokenHash = localTokenPrefix,
                        transport = transportName,
                    )
                )
            }
            is BootstrapWireFrame.HelloAck -> {
                session.peerHandle = frame.fromHandle
                session.remoteTokenPrefix = frame.fromTokenHash
                peerSessions[frame.fromHandle] = session
                addressToSession[session.device.address] = session
            }
            is BootstrapWireFrame.Signal -> {
                if (frame.message.peerHandle == localHandle) incomingBus.emit(frame.message)
            }
        }
    }

    private fun metadataJson(): String = JSONObject()
        .put("handle", localHandle)
        .put("deviceId", localDeviceId)
        .put("tokenPrefix", localTokenPrefix)
        .put("l2capPsm", l2capPsm)
        .toString()

    private fun openL2capClient(session: BlePeerSession, psm: Int) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || session.isL2capOpen()) return
        scope.launch {
            runCatching {
                val socket = session.device.createInsecureL2capChannel(psm)
                socket.connect()
                registerL2capSocket(socket, hintedHandle = session.peerHandle)
            }
        }
    }

    private fun processRemoteMetadata(gatt: BluetoothGatt, raw: ByteArray) {
        val session = addressToSession[gatt.device.address] ?: return
        val json = runCatching { JSONObject(String(raw, Charsets.UTF_8)) }.getOrNull() ?: return
        val tokenPrefix = json.optString("tokenPrefix")
        session.remoteTokenPrefix = tokenPrefix
        tokenPrefixToHandle[tokenPrefix]?.let { handle ->
            session.peerHandle = handle
            peerSessions[handle] = session
        }
        val psm = json.optInt("l2capPsm", -1)
        if (psm > 0) openL2capClient(session, psm)
        session.sendViaGatt(
            BootstrapWireFrame.Hello(
                targetToken = peerHints[session.peerHandle]?.peerBootstrapToken.orEmpty(),
                fromHandle = localHandle,
                fromDeviceId = localDeviceId,
                fromTokenHash = localTokenPrefix,
                transport = transportName,
            )
        )
    }

    private fun hasBlePermissions(): Boolean {
        val scan = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) Manifest.permission.BLUETOOTH_SCAN else Manifest.permission.BLUETOOTH
        val connect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) Manifest.permission.BLUETOOTH_CONNECT else Manifest.permission.BLUETOOTH
        val advertise = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) Manifest.permission.BLUETOOTH_ADVERTISE else Manifest.permission.BLUETOOTH_ADMIN
        return listOf(scan, connect, advertise).all { ContextCompat.checkSelfPermission(appContext, it) == PackageManager.PERMISSION_GRANTED }
    }

    private val advertiseCallback = object : AdvertiseCallback() {}

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val tokenPrefix = result.scanRecord?.getServiceData(ParcelUuid(SERVICE_UUID))?.toString(Charsets.UTF_8).orEmpty()
            if (tokenPrefix.isBlank() || tokenPrefix !in tokenPrefixToHandle || !connectingAddresses.add(result.device.address)) return
            val session = addressToSession[result.device.address] ?: BlePeerSession(device = result.device, peerHandle = tokenPrefixToHandle[tokenPrefix].orEmpty())
            addressToSession[result.device.address] = session
            result.device.connectGatt(appContext, false, clientCallback)?.also { gatt ->
                session.gatt = gatt
                if (session.peerHandle.isNotBlank()) peerSessions[session.peerHandle] = session
            }
        }
    }

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                addressToSession[device.address] = addressToSession[device.address] ?: BlePeerSession(device = device)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                addressToSession[device.address]?.detachGattOnly()
                connectingAddresses.remove(device.address)
            }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic) {
            if (characteristic.uuid == METADATA_UUID) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, metadataJson().toByteArray(Charsets.UTF_8))
            } else {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
            }
        }

        override fun onCharacteristicWriteRequest(device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
            val session = addressToSession[device.address] ?: BlePeerSession(device = device).also { addressToSession[device.address] = it }
            if (characteristic.uuid == UPLINK_UUID) {
                session.gattAssembler.push(value)?.let { frame ->
                    scope.launch { handleWireFrame(session, frame) }
                }
            }
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
        }

        override fun onDescriptorWriteRequest(device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray) {
            if (descriptor.uuid == CCCD_UUID) {
                val session = addressToSession[device.address] ?: BlePeerSession(device = device).also { addressToSession[device.address] = it }
                session.notificationsEnabled = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            }
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            }
        }
    }

    private val clientCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val session = addressToSession[gatt.device.address] ?: BlePeerSession(device = gatt.device).also { addressToSession[gatt.device.address] = it }
            session.gatt = gatt
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                gatt.discoverServices()
                runCatching { gatt.requestMtu(512) }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                session.detachGattOnly()
                connectingAddresses.remove(gatt.device.address)
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val service = gatt.getService(SERVICE_UUID) ?: return
            val session = addressToSession[gatt.device.address] ?: return
            session.metadataCharacteristic = service.getCharacteristic(METADATA_UUID)
            session.uplinkCharacteristic = service.getCharacteristic(UPLINK_UUID)
            session.downlinkCharacteristic = service.getCharacteristic(DOWNLINK_UUID)
            session.downlinkCharacteristic?.getDescriptor(CCCD_UUID)?.let { descriptor ->
                gatt.setCharacteristicNotification(session.downlinkCharacteristic, true)
                descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                gatt.writeDescriptor(descriptor)
            }
            session.metadataCharacteristic?.let(gatt::readCharacteristic)
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == METADATA_UUID) {
                processRemoteMetadata(gatt, characteristic.value ?: ByteArray(0))
            }
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == METADATA_UUID) {
                processRemoteMetadata(gatt, value)
            }
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            val session = addressToSession[gatt.device.address] ?: return
            session.gattAssembler.push(characteristic.value ?: ByteArray(0))?.let { frame ->
                scope.launch { handleWireFrame(session, frame) }
            }
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            val session = addressToSession[gatt.device.address] ?: return
            session.gattAssembler.push(value)?.let { frame ->
                scope.launch { handleWireFrame(session, frame) }
            }
        }
    }

    private data class BlePeerSession(
        val device: BluetoothDevice,
        var peerHandle: String = "",
        var gatt: BluetoothGatt? = null,
        var metadataCharacteristic: BluetoothGattCharacteristic? = null,
        var uplinkCharacteristic: BluetoothGattCharacteristic? = null,
        var downlinkCharacteristic: BluetoothGattCharacteristic? = null,
        var l2capSocket: BluetoothSocket? = null,
        var l2capReader: BufferedReader? = null,
        var l2capWriter: BufferedWriter? = null,
        var remoteTokenPrefix: String = "",
        var notificationsEnabled: Boolean = false,
        val gattAssembler: GattChunkAssembler = GattChunkAssembler(),
    ) {
        fun attachL2cap(socket: BluetoothSocket) {
            l2capSocket = socket
            l2capReader = BufferedReader(InputStreamReader(socket.inputStream, Charsets.UTF_8))
            l2capWriter = BufferedWriter(OutputStreamWriter(socket.outputStream, Charsets.UTF_8))
        }

        fun detachL2cap() {
            runCatching { l2capSocket?.close() }
            l2capSocket = null
            l2capReader = null
            l2capWriter = null
        }

        fun detachGattOnly() {
            runCatching { gatt?.close() }
            gatt = null
            metadataCharacteristic = null
            uplinkCharacteristic = null
            downlinkCharacteristic = null
            notificationsEnabled = false
        }

        fun close() {
            detachGattOnly()
            detachL2cap()
        }

        fun isL2capOpen(): Boolean = l2capSocket?.isConnected == true

        fun sendViaL2cap(frame: BootstrapWireFrame): Boolean {
            val writer = l2capWriter ?: return false
            return runCatching {
                writer.write(BootstrapWireCodec.encodeLine(frame))
                writer.flush()
                true
            }.getOrDefault(false)
        }

        fun sendViaGatt(frame: BootstrapWireFrame): Boolean {
            val gatt = gatt ?: return false
            val uplink = uplinkCharacteristic
            if (uplink != null) {
                return GattChunking.encode(frame).all { chunk ->
                    uplink.value = chunk
                    runCatching { gatt.writeCharacteristic(uplink) }.getOrDefault(false)
                }
            }
            return false
        }
    }

    private class GattChunkAssembler {
        private val chunks = ConcurrentHashMap<String, MutableMap<Int, String>>()
        private val expectedCounts = ConcurrentHashMap<String, Int>()

        fun push(raw: ByteArray): BootstrapWireFrame? {
            val json = JSONObject(String(raw, Charsets.UTF_8))
            val frameId = json.getString("frameId")
            val index = json.getInt("index")
            val count = json.getInt("count")
            val chunk = json.getString("chunk")
            val bucket = chunks.getOrPut(frameId) { mutableMapOf<Int, String>() }
            bucket[index] = chunk
            expectedCounts[frameId] = count
            if (bucket.size != count) return null
            val base64 = buildString {
                for (i in 0 until count) append(bucket[i].orEmpty())
            }
            chunks.remove(frameId)
            expectedCounts.remove(frameId)
            val rawFrame = String(Base64.getDecoder().decode(base64), Charsets.UTF_8)
            return BootstrapWireCodec.decode(rawFrame)
        }
    }

    private object GattChunking {
        fun encode(frame: BootstrapWireFrame, chunkSize: Int = 160): List<ByteArray> {
            val raw = Base64.getEncoder().encodeToString(BootstrapWireCodec.encode(frame).toByteArray(Charsets.UTF_8))
            val frameId = UUID.randomUUID().toString()
            val parts = raw.chunked(chunkSize)
            return parts.mapIndexed { index, part ->
                JSONObject()
                    .put("frameId", frameId)
                    .put("index", index)
                    .put("count", parts.size)
                    .put("chunk", part)
                    .toString()
                    .toByteArray(Charsets.UTF_8)
            }
        }
    }

    private companion object {
        val SERVICE_UUID: UUID = UUID.fromString("4af857ca-7d13-4dd8-9a25-7e87d3dd6b9b")
        val METADATA_UUID: UUID = UUID.fromString("4af857ca-7d13-4dd8-9a25-7e87d3dd6b9c")
        val UPLINK_UUID: UUID = UUID.fromString("4af857ca-7d13-4dd8-9a25-7e87d3dd6b9d")
        val DOWNLINK_UUID: UUID = UUID.fromString("4af857ca-7d13-4dd8-9a25-7e87d3dd6b9e")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
