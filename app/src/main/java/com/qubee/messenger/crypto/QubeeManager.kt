package com.qubee.messenger.crypto

import android.util.Log

object QubeeManager {

    private const val TAG = "QubeeManager"

    init {
        try {
            System.loadLibrary("qubee_crypto")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native library", e)
        }
    }

    fun initialize() {
        try {
            val success = nativeInitialize()
            if (success) {
                Log.d(TAG, "Qubee native library initialized successfully")
            } else {
                Log.e(TAG, "Failed to initialize Qubee native library")
            }
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Error initializing Qubee native library", e)
        }
    }

    external fun nativeInitialize(): Boolean
    external fun nativeGenerateIdentityKeyPair(): ByteArray?
    external fun nativeCreateRatchetSession(contactId: String, theirPublicKey: ByteArray, isInitiator: Boolean): ByteArray?
    external fun nativeEncryptMessage(sessionId: String, plaintext: ByteArray): ByteArray?
    external fun nativeDecryptMessage(sessionId: String, ciphertext: ByteArray): ByteArray?
    external fun nativeCleanup()
}
