package com.qubee.messenger.crypto

import com.qubee.messenger.network.NetworkCallback
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class QubeeManager @Inject constructor() {

    private var isInitialized = false

    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            if (isInitialized) return@withContext true
            System.loadLibrary("qubee_crypto")
            
            val result = nativeInitialize()
            if (result) {
                isInitialized = true
                Timber.d("Qubee initialized")
            }
            result
        } catch (e: Exception) {
            Timber.e(e, "Init failed")
            false
        }
    }

    fun setNetworkCallback(callback: NetworkCallback) {
        if (!isInitialized) {
            Timber.e("Cannot register callback: Qubee not initialized")
            return
        }
        nativeRegisterCallback(callback)
    }

    suspend fun startNetworkNode(bootstrapNodes: String = ""): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext false
        nativeStartNetwork(bootstrapNodes)
    }
    
    /**
     * Sends a payload to a specific peer (or broadcasts it) via the P2P network.
     * @param peerId The ID of the recipient (or topic/group ID).
     * @param data The encrypted byte array.
     */
    suspend fun sendP2PMessage(peerId: String, data: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            Timber.e("Cannot send P2P message: Qubee not initialized")
            return@withContext false
        }
        nativeSendP2PMessage(peerId, data)
    }

    // --- Wrapper Methods ---

    suspend fun generateIdentityKeyPair(): IdentityKeyPair? = withContext(Dispatchers.IO) {
        val bytes = nativeGenerateIdentityKeyPair()
        if (bytes != null) IdentityKeyPair.fromBytes(bytes) else null
    }

    suspend fun createRatchetSession(
        contactId: String,
        theirPublicKey: ByteArray,
        isInitiator: Boolean
    ): RatchetSession? = withContext(Dispatchers.IO) {
        val bytes = nativeCreateRatchetSession(contactId, theirPublicKey, isInitiator)
        if (bytes != null) RatchetSession.fromBytes(bytes) else null
    }

    suspend fun encryptMessage(sessionId: String, plaintext: String): EncryptedMessage? = withContext(Dispatchers.IO) {
        val bytes = nativeEncryptMessage(sessionId, plaintext.toByteArray())
        if (bytes != null) EncryptedMessage.fromBytes(bytes) else null
    }

    suspend fun decryptMessage(sessionId: String, encryptedMessage: EncryptedMessage): String? = withContext(Dispatchers.IO) {
        val bytes = nativeDecryptMessage(sessionId, encryptedMessage.toBytes())
        if (bytes != null) String(bytes) else null
    }

    // We can add wrapper for encryptSignaling if needed by ViewModel, 
    // but typically signaling is internal or handled by CallManager.
    suspend fun encryptSignaling(
        sessionId: String,
        callId: String,
        sdpJson: String
    ): EncryptedMessage? = withContext(Dispatchers.IO) {
        val bytes = nativeEncryptSignaling(sessionId, callId, sdpJson)
        if (bytes != null) EncryptedMessage.fromBytes(bytes) else null
    }
    
    // --- Native Definitions ---
    private external fun nativeInitialize(): Boolean
    private external fun nativeRegisterCallback(callback: NetworkCallback)
    private external fun nativeStartNetwork(bootstrapNodes: String): Boolean
    private external fun nativeSendP2PMessage(peerId: String, data: ByteArray): Boolean // NEW

    private external fun nativeGenerateIdentityKeyPair(): ByteArray?
    private external fun nativeCreateRatchetSession(cid: String, key: ByteArray, init: Boolean): ByteArray?
    private external fun nativeEncryptMessage(sid: String, data: ByteArray): ByteArray?
    private external fun nativeDecryptMessage(sid: String, data: ByteArray): ByteArray?
    private external fun nativeEncryptSignaling(sid: String, callId: String, sdp: String): ByteArray?
    
    // Legacy / Utils
    private external fun nativeGenerateEphemeralKeys(): ByteArray?
    private external fun nativeVerifyIdentityKey(cid: String, key: ByteArray, sig: ByteArray): Boolean
    private external fun nativeGenerateSAS(k1: ByteArray, k2: ByteArray): String?
    private external fun nativeEncryptFile(sid: String, data: ByteArray): ByteArray?
    private external fun nativeDecryptFile(sid: String, data: ByteArray): ByteArray?
    
    external fun nativeCleanup()
}
