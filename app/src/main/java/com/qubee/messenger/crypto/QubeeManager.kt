package com.qubee.messenger.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

/**
 * QubeeManager handles all cryptographic operations by interfacing with the Rust Qubee library
 * through JNI (Java Native Interface).
 */
@Singleton
class QubeeManager @Inject constructor() {

    private var isInitialized = false

    /**
     * Initialize the Qubee cryptographic system
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            if (isInitialized) {
                return@withContext true
            }

            val result = nativeInitialize()
            if (result) {
                isInitialized = true
                Timber.d("Qubee cryptographic system initialized successfully")
            } else {
                Timber.e("Failed to initialize Qubee cryptographic system")
            }
            result
        } catch (e: Exception) {
            Timber.e(e, "Error initializing Qubee cryptographic system")
            false
        }
    }

    /**
     * Generate a new identity key pair
     */
    suspend fun generateIdentityKeyPair(): IdentityKeyPair? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            val keyPairBytes = nativeGenerateIdentityKeyPair()
            if (keyPairBytes != null) {
                IdentityKeyPair.fromBytes(keyPairBytes)
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.e(e, "Error generating identity key pair")
            null
        }
    }

    /**
     * Create a new hybrid ratchet session with a contact
     */
    suspend fun createRatchetSession(
        contactId: String,
        theirPublicKey: ByteArray,
        isInitiator: Boolean
    ): RatchetSession? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            val sessionBytes = nativeCreateRatchetSession(contactId, theirPublicKey, isInitiator)
            if (sessionBytes != null) {
                RatchetSession.fromBytes(sessionBytes)
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.e(e, "Error creating ratchet session")
            null
        }
    }

    /**
     * Encrypt a message using the hybrid ratchet
     */
    suspend fun encryptMessage(
        sessionId: String,
        plaintext: String
    ): EncryptedMessage? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            val encryptedBytes = nativeEncryptMessage(sessionId, plaintext.toByteArray())
            if (encryptedBytes != null) {
                EncryptedMessage.fromBytes(encryptedBytes)
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.e(e, "Error encrypting message")
            null
        }
    }

    /**
     * Decrypt a message using the hybrid ratchet
     */
    suspend fun decryptMessage(
        sessionId: String,
        encryptedMessage: EncryptedMessage
    ): String? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            val decryptedBytes = nativeDecryptMessage(sessionId, encryptedMessage.toBytes())
            if (decryptedBytes != null) {
                String(decryptedBytes)
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.e(e, "Error decrypting message")
            null
        }
    }

    /**
     * Generate ephemeral keys for key exchange
     */
    suspend fun generateEphemeralKeys(): EphemeralKeyPair? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            val keyPairBytes = nativeGenerateEphemeralKeys()
            if (keyPairBytes != null) {
                EphemeralKeyPair.fromBytes(keyPairBytes)
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.e(e, "Error generating ephemeral keys")
            null
        }
    }

    /**
     * Verify a contact's identity key
     */
    suspend fun verifyIdentityKey(
        contactId: String,
        identityKey: ByteArray,
        signature: ByteArray
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext false
            }

            nativeVerifyIdentityKey(contactId, identityKey, signature)
        } catch (e: Exception) {
            Timber.e(e, "Error verifying identity key")
            false
        }
    }

    /**
     * Generate a Short Authentication String (SAS) for key verification
     */
    suspend fun generateSAS(
        ourKey: ByteArray,
        theirKey: ByteArray
    ): String? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            nativeGenerateSAS(ourKey, theirKey)
        } catch (e: Exception) {
            Timber.e(e, "Error generating SAS")
            null
        }
    }

    /**
     * Encrypt file data
     */
    suspend fun encryptFile(
        sessionId: String,
        fileData: ByteArray
    ): EncryptedFile? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            val encryptedBytes = nativeEncryptFile(sessionId, fileData)
            if (encryptedBytes != null) {
                EncryptedFile.fromBytes(encryptedBytes)
            } else {
                null
            }
        } catch (e: Exception) {
            Timber.e(e, "Error encrypting file")
            null
        }
    }

    /**
     * Decrypt file data
     */
    suspend fun decryptFile(
        sessionId: String,
        encryptedFile: EncryptedFile
    ): ByteArray? = withContext(Dispatchers.IO) {
        try {
            if (!isInitialized) {
                Timber.e("Qubee not initialized")
                return@withContext null
            }

            nativeDecryptFile(sessionId, encryptedFile.toBytes())
        } catch (e: Exception) {
            Timber.e(e, "Error decrypting file")
            null
        }
    }

    /**
     * Clean up resources
     */
    fun cleanup() {
        try {
            if (isInitialized) {
                nativeCleanup()
                isInitialized = false
                Timber.d("Qubee cryptographic system cleaned up")
            }
        } catch (e: Exception) {
            Timber.e(e, "Error cleaning up Qubee")
        }
    }

    // Native method declarations - these will be implemented in Rust
    private external fun nativeInitialize(): Boolean
    private external fun nativeGenerateIdentityKeyPair(): ByteArray?
    private external fun nativeCreateRatchetSession(
        contactId: String,
        theirPublicKey: ByteArray,
        isInitiator: Boolean
    ): ByteArray?
    private external fun nativeEncryptMessage(sessionId: String, plaintext: ByteArray): ByteArray?
    private external fun nativeDecryptMessage(sessionId: String, ciphertext: ByteArray): ByteArray?
    private external fun nativeGenerateEphemeralKeys(): ByteArray?
    private external fun nativeVerifyIdentityKey(
        contactId: String,
        identityKey: ByteArray,
        signature: ByteArray
    ): Boolean
    private external fun nativeGenerateSAS(ourKey: ByteArray, theirKey: ByteArray): String?
    private external fun nativeEncryptFile(sessionId: String, fileData: ByteArray): ByteArray?
    private external fun nativeDecryptFile(sessionId: String, encryptedData: ByteArray): ByteArray?
    private external fun nativeCleanup()
}

