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

            // Pass the app's private dir to Rust so the encrypted keystore
            // lands inside it. Hard-coding the package path inside Rust
            // (the previous behaviour) silently broke whenever the
            // applicationId changed.
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

    // The Ratchet/Sealed-Sender message-encryption wrappers
    // (generateIdentityKeyPair / createRatchetSession / encryptMessage /
    // decryptMessage / encryptSignaling) used to live here, but their
    // Rust counterparts were placeholder stubs that never actually
    // tied into a real `SecureMessenger`. They've been removed until
    // the message pipeline is implemented end-to-end; QubeeManager only
    // exposes JNI surfaces backed by working code.

    // --- Onboarding & invite links ---

    /**
     * Generate a fresh hybrid identity, hybrid-sign the onboarding bundle,
     * persist the keypair to the encrypted keystore, and return a JSON
     * document with the `qubee://identity/...` deep link plus QR-friendly
     * metadata.
     */
    suspend fun createOnboardingBundle(
        displayName: String,
        userId: String
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeCreateOnboardingBundle(displayName, userId)
    }

    /**
     * Re-export the previously persisted onboarding bundle, if any.
     * Returns `null` on first launch (no identity yet).
     */
    suspend fun loadOnboardingBundle(): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeLoadOnboardingBundle()
    }

    /**
     * Verify a peer's `qubee://identity/...` share link and return their
     * identity metadata as JSON. Returns null if the link is malformed or
     * its embedded ZK proof fails verification.
     */
    suspend fun verifyOnboardingLink(link: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeVerifyOnboardingLink(link)
    }

    /**
     * Build a `qubee://invite/<token>` link from a JSON invitation
     * descriptor. The Qubee-wide 16-member cap is encoded into the link.
     */
    suspend fun buildInviteLink(invitationJson: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeBuildInviteLink(invitationJson)
    }

    /**
     * Create a brand new group owned by the active local identity.
     * Returns the JSON `{group_id_hex, name, owner_id_hex}` produced
     * by Rust, or null if onboarding hasn't happened yet.
     */
    suspend fun createGroup(name: String, description: String = ""): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            nativeCreateGroup(name, description)
        }

    /**
     * Mint a new invitation for a group we own. Returns the same JSON
     * shape `nativeBuildInviteLink` produces, plus the underlying
     * invitation_code so the UI can show "X joins remaining".
     *
     * `expiresAtSeconds` and `maxUses` accept negative values to mean
     * "no limit"; the JNI uses sentinel-negative values to keep the
     * C ABI simple.
     */
    suspend fun createGroupInvite(
        groupIdHex: String,
        expiresAtSeconds: Long = -1L,
        maxUses: Int = -1,
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeCreateGroupInvite(groupIdHex, expiresAtSeconds, maxUses)
    }

    /**
     * Remove a member from a group we own. Internally rotates the
     * group's symmetric key and broadcasts a signed `KeyRotation` so
     * the remaining members converge on the fresh key — the kicked
     * member can no longer decrypt new traffic.
     */
    suspend fun removeMember(
        groupIdHex: String,
        memberIdHex: String,
        reason: String = "",
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeRemoveMember(groupIdHex, memberIdHex, reason)
    }

    /**
     * Parse a `qubee://invite/<token>` deep link and return its contents
     * as JSON. Returns null if the link is malformed.
     */
    suspend fun parseInviteLink(link: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeParseInviteLink(link)
    }

    /**
     * Accept a scanned/pasted Qubee invite. Records the acceptance in
     * the encrypted group keystore so it survives restarts; the actual
     * group-membership confirmation comes back over the network once
     * the inviter's device gets the handshake.
     */
    suspend fun acceptInvite(link: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeAcceptInvite(link)
    }

    /** List invites the local user has accepted-but-not-yet-confirmed. */
    suspend fun listAcceptedInvites(): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        nativeListAcceptedInvites()
    }

    // --- Native Definitions ---
    private external fun nativeInitialize(dataDir: String): Boolean
    private external fun nativeRegisterCallback(callback: NetworkCallback)
    private external fun nativeStartNetwork(bootstrapNodes: String): Boolean
    private external fun nativeSendP2PMessage(peerId: String, data: ByteArray): Boolean

    // Onboarding / identity
    private external fun nativeCreateOnboardingBundle(displayName: String, userId: String): String?
    private external fun nativeLoadOnboardingBundle(): String?
    private external fun nativeVerifyOnboardingLink(link: String): String?

    // Group invite links
    private external fun nativeBuildInviteLink(invitationJson: String): String?
    private external fun nativeParseInviteLink(link: String): String?
    private external fun nativeAcceptInvite(link: String): String?
    private external fun nativeListAcceptedInvites(): String?

    // Group lifecycle
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

    external fun nativeCleanup()
}
