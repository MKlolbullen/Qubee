// app/src/main/java/com/qubee/messenger/crypto/QubeeManager.kt

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

    /**
     * Registers the callback interface for network events (P2P).
     */
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

    // --- Native Definitions ---
    private external fun nativeInitialize(): Boolean
    private external fun nativeRegisterCallback(callback: NetworkCallback) // NEW
    private external fun nativeStartNetwork(bootstrapNodes: String): Boolean
    
    private external fun nativeGenerateIdentityKeyPair(): ByteArray?
    private external fun nativeCreateRatchetSession(cid: String, key: ByteArray, init: Boolean): ByteArray?
    private external fun nativeEncryptMessage(sid: String, data: ByteArray): ByteArray?
    private external fun nativeDecryptMessage(sid: String, data: ByteArray): ByteArray?
    
    // Cleanup
    external fun nativeCleanup()
}
