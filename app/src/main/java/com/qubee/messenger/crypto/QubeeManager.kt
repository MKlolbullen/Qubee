package com.qubee.messenger.crypto

import android.content.Context
import com.qubee.messenger.network.NetworkCallback
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class QubeeManager @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    private var isInitialized = false

    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            if (isInitialized) return@withContext true
            System.loadLibrary("qubee_crypto")

            val result = nativeInitialize(context.filesDir.absolutePath)
            if (result) {
                isInitialized = true
                Timber.d("Qubee initialized at %s", context.filesDir.absolutePath)
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

    suspend fun sendP2PMessage(peerId: String, data: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            Timber.e("Cannot send P2P message: Qubee not initialized")
            return@withContext false
        }
        nativeSendP2PMessage(peerId, data)
    }

    /**
     * Direct-message encryption is owned by Rust.
     *
     * Kotlin may request an encrypted envelope for transport/storage, but it
     * must never implement fallback cryptography or plaintext compatibility
     * envelopes. If the native symbol is missing, this fails closed and returns
     * null after logging the linkage error.
     */
    suspend fun encryptMessage(sessionId: String, plaintext: String): EncryptedMessage? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeEncryptMessage(sessionId, plaintext)?.let(EncryptedMessage::fromBytes)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust direct-message encryption JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust direct-message encryption failed")
            null
        }
    }

    suspend fun decryptMessage(sessionId: String, encryptedMessage: EncryptedMessage): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeDecryptMessage(sessionId, encryptedMessage.toBytes())
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust direct-message decryption JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust direct-message decryption failed")
            null
        }
    }

    suspend fun encryptFile(sessionId: String, fileData: ByteArray): EncryptedFile? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeEncryptFile(sessionId, fileData)?.let(EncryptedFile::fromBytes)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust file-encryption JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust file encryption failed")
            null
        }
    }

    suspend fun decryptFile(sessionId: String, encryptedFile: EncryptedFile): ByteArray? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeDecryptFile(sessionId, encryptedFile.toBytes())
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust file-decryption JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust file decryption failed")
            null
        }
    }

    suspend fun verifyIdentityKey(contactId: String, identityKey: ByteArray, verificationData: ByteArray): Boolean =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext false
            try {
                nativeVerifyIdentityKey(contactId, identityKey, verificationData)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust identity verification JNI is not linked")
                false
            } catch (e: Exception) {
                Timber.e(e, "Rust identity verification failed")
                false
            }
        }

    suspend fun generateSAS(ourIdentityKey: ByteArray, peerIdentityKey: ByteArray): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeGenerateSAS(ourIdentityKey, peerIdentityKey)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust SAS generation JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Rust SAS generation failed")
                null
            }
        }

    // --- Onboarding & invite links ---

    suspend fun createOnboardingBundle(
        displayName: String,
        userId: String
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeCreateOnboardingBundle(displayName, userId)
    }

    suspend fun loadOnboardingBundle(): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeLoadOnboardingBundle()
    }

    /**
     * Verify a peer's `qubee://identity/...` share link and return their
     * identity metadata as JSON. Returns null if the link is malformed
     * or its embedded hybrid Ed25519+Dilithium-2 signature fails to
     * verify against the advertised public key.
     */
    suspend fun verifyOnboardingLink(link: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeVerifyOnboardingLink(link)
    }

    suspend fun buildInviteLink(invitationJson: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeBuildInviteLink(invitationJson)
    }

    suspend fun createGroup(name: String, description: String = ""): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            nativeCreateGroup(name, description)
        }

    suspend fun createGroupInvite(
        groupIdHex: String,
        expiresAtSeconds: Long = -1L,
        maxUses: Int = -1,
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeCreateGroupInvite(groupIdHex, expiresAtSeconds, maxUses)
    }

    suspend fun removeMember(
        groupIdHex: String,
        memberIdHex: String,
        reason: String = "",
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeRemoveMember(groupIdHex, memberIdHex, reason)
    }

    suspend fun sendGroupMessage(
        groupIdHex: String,
        plaintext: ByteArray,
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeSendGroupMessage(groupIdHex, plaintext)
    }

    suspend fun resetIdentity(): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) {
            return@withContext nativeResetIdentity(context.filesDir.absolutePath)
        }
        val ok = nativeResetIdentity(context.filesDir.absolutePath)
        if (ok) {
            isInitialized = false
            Timber.d("Qubee identity reset; core needs re-initialise")
        }
        ok
    }

    suspend fun parseInviteLink(link: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeParseInviteLink(link)
    }

    suspend fun acceptInvite(link: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeAcceptInvite(link)
    }

    suspend fun listAcceptedInvites(): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeListAcceptedInvites()
    }

    private external fun nativeInitialize(dataDir: String): Boolean
    private external fun nativeRegisterCallback(callback: NetworkCallback)
    private external fun nativeStartNetwork(bootstrapNodes: String): Boolean
    private external fun nativeSendP2PMessage(peerId: String, data: ByteArray): Boolean

    // Direct-message/session JNI owned by Rust.
    private external fun nativeEncryptMessage(sessionId: String, plaintext: String): ByteArray?
    private external fun nativeDecryptMessage(sessionId: String, encryptedEnvelope: ByteArray): String?
    private external fun nativeEncryptFile(sessionId: String, fileData: ByteArray): ByteArray?
    private external fun nativeDecryptFile(sessionId: String, encryptedEnvelope: ByteArray): ByteArray?
    private external fun nativeVerifyIdentityKey(contactId: String, identityKey: ByteArray, verificationData: ByteArray): Boolean
    private external fun nativeGenerateSAS(ourIdentityKey: ByteArray, peerIdentityKey: ByteArray): String?

    private external fun nativeCreateOnboardingBundle(displayName: String, userId: String): String?
    private external fun nativeLoadOnboardingBundle(): String?
    private external fun nativeVerifyOnboardingLink(link: String): String?

    private external fun nativeBuildInviteLink(invitationJson: String): String?
    private external fun nativeParseInviteLink(link: String): String?
    private external fun nativeAcceptInvite(link: String): String?
    private external fun nativeListAcceptedInvites(): String?

    private external fun nativeCreateGroup(name: String, description: String): String?
    private external fun nativeCreateGroupInvite(
        groupIdHex: String,
        expiresAtSeconds: Long,
        maxUses: Int,
    ): String?
    private external fun nativeRemoveMember(
        groupIdHex: String,
        memberIdHex: String,
        reason: String,
    ): String?
    private external fun nativeSendGroupMessage(
        groupIdHex: String,
        plaintext: ByteArray,
    ): String?
    private external fun nativeResetIdentity(dataDir: String): Boolean

    external fun nativeCleanup()
}
