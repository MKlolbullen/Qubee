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

    /**
     * Compute the canonical 8-byte BLAKE3 fingerprint of a peer's
     * `IdentityKey`, formatted as `"AABB CCDD EEFF GGHH"`. Use this
     * — not the Kotlin `ByteArray.toFingerprint` extension — when
     * displaying a fingerprint for OOB compare; it matches what
     * Rust's `IdentityKey::fingerprint()` produces, so two devices
     * comparing fingerprints are comparing the same string.
     */
    suspend fun computeFingerprint(identityKey: ByteArray): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeComputeFingerprint(identityKey)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust fingerprint JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Rust fingerprint computation failed")
                null
            }
        }

    /**
     * Return the locally-active identity's own fingerprint, formatted
     * as `"AABB CCDD EEFF GGHH"`. Used by the verify dialog to render
     * the local user's self-fingerprint as a QR code so the peer can
     * scan it — closes the "what does the peer scan to verify *me*"
     * direction of the OOB compare ceremony.
     *
     * Returns null if onboarding hasn't completed yet (no active
     * identity in the keystore).
     */
    suspend fun getMyFingerprint(): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeGetMyFingerprint()
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust my-fingerprint JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Rust my-fingerprint computation failed")
                null
            }
        }

    /**
     * Read the `sender_id` field out of a `GroupMessageEnvelope`
     * wire envelope without decrypting. The signed body carries
     * this in the clear (authenticated, not confidential), so we
     * can identify which Qubee identity sent the packet before
     * going through the AEAD path. Used by `MessageService` to
     * populate `Contact.peerId` on first inbound from a known
     * identity.
     *
     * Returns the sender's identity id as a 64-character hex
     * string, or null if `wire` doesn't parse as an envelope.
     */
    suspend fun inspectEnvelopeSender(wire: ByteArray): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeInspectEnvelopeSender(wire)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust envelope-inspect JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Envelope inspection failed")
                null
            }
        }

    /**
     * Compute the Short Authentication String (SAS) between the
     * locally active identity and a peer's `IdentityKey` bytes.
     * Both peers' devices independently compute the same string
     * (Rust orders the byte buffers lexicographically before the
     * BLAKE3 hash), so the user-side compare ceremony reduces to
     * "do these two strings match?" — readable over voice in a
     * few seconds, no typing.
     *
     * Returns the SAS as `"NNNN NNNN"` on success, or null on any
     * failure (no active identity, invalid peer key, JNI not
     * linked, etc.).
     */
    suspend fun generateSASForContact(peerIdentityKey: ByteArray): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeGenerateSASForContact(peerIdentityKey)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust SAS-for-contact JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "SAS-for-contact computation failed")
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

    /**
     * Promote (or demote) a member of a group we own to a new role.
     * `newRole` must be one of `Owner`, `Admin`, `Moderator`,
     * `Member`, `Observer` (case-insensitive Rust-side; the native
     * code rejects anything else). Returns the JSON envelope from
     * `nativePromoteMember` on success, null if the JNI call failed
     * (not owner, member not found, role string unknown, …).
     */
    suspend fun promoteMember(
        groupIdHex: String,
        memberIdHex: String,
        newRole: String,
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativePromoteMember(groupIdHex, memberIdHex, newRole)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust promote-member JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust promote-member failed")
            null
        }
    }

    /**
     * List the active members of a group, as returned by the Rust
     * core. JSON shape is an array of
     * `{identity_id_hex, display_name, role, is_active, joined_at}`
     * — see `Java_com_qubee_messenger_crypto_QubeeManager_nativeListGroupMembers`
     * in `src/jni_api.rs`. Returns null if the group isn't in the
     * local Rust view (e.g., the user accepted an invite but the
     * JoinAccepted handshake hasn't landed yet, so the Rust core
     * still doesn't know about the group).
     */
    /**
     * The locally-active identity's `IdentityId` as a 64-char hex
     * string. Used to flag "this row is you" in the Group Details
     * member list and to pass our own id into `removeMember` for
     * the "Leave group" action.
     */
    suspend fun getMyIdentityIdHex(): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeGetMyIdentityIdHex()
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust my-identity-id JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust my-identity-id failed")
            null
        }
    }

    suspend fun listGroupMembers(groupIdHex: String): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeListGroupMembers(groupIdHex)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust list-group-members JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust list-group-members failed")
            null
        }
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
    private external fun nativeComputeFingerprint(identityKey: ByteArray): String?
    private external fun nativeInspectEnvelopeSender(wire: ByteArray): String?
    private external fun nativeGenerateSASForContact(peerIdentityKey: ByteArray): String?
    private external fun nativeGetMyFingerprint(): String?
    private external fun nativeListGroupMembers(groupIdHex: String): String?
    private external fun nativeGetMyIdentityIdHex(): String?

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
    private external fun nativePromoteMember(
        groupIdHex: String,
        memberIdHex: String,
        newRole: String,
    ): String?
    private external fun nativeSendGroupMessage(
        groupIdHex: String,
        plaintext: ByteArray,
    ): String?
    private external fun nativeResetIdentity(dataDir: String): Boolean

    external fun nativeCleanup()
}
