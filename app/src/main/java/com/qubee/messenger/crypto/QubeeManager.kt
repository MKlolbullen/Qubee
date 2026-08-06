package com.qubee.messenger.crypto

import android.content.Context
import com.qubee.messenger.network.NetworkCallback
import com.qubee.messenger.security.DatabaseKeyHolder
import com.qubee.messenger.security.SqlCipherKeyProvider
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class QubeeManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val keyProvider: SqlCipherKeyProvider,
    private val keyHolder: DatabaseKeyHolder,
) {

    // @Volatile: read/written from Dispatchers.IO by concurrent
    // initialize() callers. The Rust INITIALIZED mutex already makes
    // native init idempotent; this just keeps the Kotlin-side flag's
    // visibility correct across threads.
    @Volatile
    private var isInitialized = false

    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            if (isInitialized) return@withContext true
            System.loadLibrary("qubee_crypto")

            // Fetch the hardware-Keystore-derived passphrase that
            // protects the Rust core's on-disk private identity keys.
            // Fail closed: if the Keystore is unavailable we refuse to
            // initialise rather than fall back to an unprotected
            // keystore. Carried as a ByteArray end-to-end (never a
            // String) so it can be zeroed after the native call — JVM
            // strings are immutable and would pin the secret in the
            // heap until GC, or forever if interned.
            // App-lock binding: when Screen Lock is on, the core
            // keystore passphrase is stored auth-bound and only lives
            // in the holder after the unlock ceremony. If it's not
            // there yet we're still locked — refuse to init (the
            // caller retries after unlock). With Screen Lock off it
            // unwraps directly under the auth-free hardware key.
            val passphrase = try {
                if (keyProvider.isAuthBindingEnabled()) {
                    keyHolder.corePassphraseCopy() ?: run {
                        Timber.d("App locked; deferring core init until unlock")
                        return@withContext false
                    }
                } else {
                    keyProvider.getOrCreateCoreKeystorePassphrase()
                }
            } catch (e: SecurityException) {
                Timber.e(e, "Keystore passphrase unavailable; refusing to init core")
                return@withContext false
            }

            val result = try {
                nativeInitialize(context.filesDir.absolutePath, passphrase)
            } finally {
                passphrase.fill(0)
            }
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

    /**
     * Build the local device's signed prekey bundle (Ratchet Stage 2).
     * Rust generates and persists fresh X25519/ML-KEM prekey material on
     * first call and returns the signed PrekeyBundle wire frame, which
     * the caller publishes on the group topic. Bundles are cached by
     * receivers but not yet consumed by send/receive (Stage 3).
     */
    suspend fun buildLocalPrekeyBundle(): ByteArray? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeBuildLocalPrekeyBundle()
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust prekey-bundle JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust prekey-bundle build failed")
            null
        }
    }

    /**
     * Verify + cache a peer's signed prekey bundle (Ratchet Stage 3d).
     * Returns the publisher's identity id as a 64-char hex string, or
     * null when the frame is malformed or its signature doesn't verify.
     * Installing a bundle is the precondition for both initiating a
     * ratchet session to that peer and accepting their first message.
     */
    suspend fun installPeerPrekeyBundle(bundleWire: ByteArray): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeInstallPeerPrekeyBundle(bundleWire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust prekey-bundle-install JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust prekey-bundle install failed")
            null
        }
    }

    /**
     * Encrypt a plaintext for one peer over the forward-secret PQXDH +
     * Double Ratchet session (Ratchet Stage 3d), establishing the
     * session from the peer's installed prekey bundle on first use.
     * Returns the QUBEE_DMS wire frame. Dark-launched: MessageService
     * still routes live 1:1 traffic through the legacy envelope; this
     * path activates only when the ratchet rollout flag flips.
     */
    suspend fun encryptDirectMessage(peerIdHex: String, plaintext: String): ByteArray? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeEncryptDirectMessage(peerIdHex, plaintext)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust ratchet-encrypt JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust ratchet encryption failed")
            null
        }
    }

    /**
     * Decrypt an inbound QUBEE_DMS frame (Ratchet Stage 3d/5),
     * establishing the responder side of the session on a
     * conversation's first message, and decode its tagged payload.
     * Returns a JSON string:
     * `{"senderId": hex, "kind": "text", "text": str}` for chat, or
     * `{"senderId": hex, "kind": "senderKeyDistribution", "groupId":
     * hex}` for a Stage 4 sender key that Rust has already
     * membership-checked and installed. Null on wrong frame type,
     * missing session/bundle, replay, tampering, or a distribution
     * from a non-member.
     */
    suspend fun decryptDirectMessage(wire: ByteArray): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeDecryptDirectMessage(wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust ratchet-decrypt JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust ratchet decryption failed")
            null
        }
    }

    /**
     * Encrypt this device's sender key for a group to one peer over the
     * 1:1 ratchet session (Ratchet Stage 5 plumbing). Call once per
     * group member when (re)distributing; the receiving side installs
     * automatically inside [decryptDirectMessage]. Returns the
     * QUBEE_DMS wire frame to send to that peer.
     */
    suspend fun createDirectDistributionMessage(peerIdHex: String, groupIdHex: String): ByteArray? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeCreateDirectDistributionMessage(peerIdHex, groupIdHex)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust distribution-message JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Rust distribution message create failed")
                null
            }
        }

    /**
     * Tear down the 1:1 ratchet session with a peer. Recovery lever for
     * a peer who reinstalled and whose fresh handshake is refused while
     * we hold the old session — after the reset their next message
     * re-establishes. Trigger only from a user action or a trust-state
     * event; in-flight messages on the old session are lost. Returns
     * the number of state entries removed, or -1 on failure.
     */
    suspend fun resetDirectSession(peerIdHex: String): Int = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext -1
        try {
            nativeResetDirectSession(peerIdHex)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust direct-session-reset JNI is not linked")
            -1
        } catch (e: Exception) {
            Timber.e(e, "Rust direct-session reset failed")
            -1
        }
    }

    /**
     * Wipe all Stage 4 sender-key state for a group, forcing fresh
     * distributions. Rust triggers this automatically on member
     * removal / key rotation; exposed for manual rekeys. Returns the
     * number of states deleted, or -1 on failure.
     */
    suspend fun resetGroupSenderState(groupIdHex: String): Int = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext -1
        try {
            nativeResetGroupSenderState(groupIdHex)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust sender-state-reset JNI is not linked")
            -1
        } catch (e: Exception) {
            Timber.e(e, "Rust sender-state reset failed")
            -1
        }
    }

    /**
     * If `wire` is a QUBEE_DMS frame, return the claimed sender's
     * identity id as a 64-char hex string without touching session
     * state; null otherwise. The claim is unauthenticated until
     * [decryptDirectMessage] succeeds — treat it as routing metadata
     * only, mirroring [inspectEnvelopeSender].
     */
    suspend fun inspectDirectMessageSender(wire: ByteArray): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeInspectDirectMessageSender(wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust direct-inspect JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Direct message inspection failed")
            null
        }
    }

    /**
     * Create (or reload) this device's sender key for a group (Ratchet
     * Stage 4) and return the distribution payload. The payload contains
     * the live chain key — deliver it ONLY via [encryptDirectMessage],
     * one copy per member, never on a plaintext or group topic.
     */
    suspend fun createSenderKeyDistribution(groupIdHex: String): ByteArray? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeCreateSenderKeyDistribution(groupIdHex)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust sender-key-create JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust sender-key distribution create failed")
            null
        }
    }

    /**
     * Install a member's sender key distribution (Ratchet Stage 4).
     * [authenticatedSenderHex] must be the sender identity proven by the
     * 1:1 channel that delivered the bytes (the id from
     * [inspectDirectMessageSender] whose [decryptDirectMessage]
     * succeeded) — Rust enforces it matches both the distribution's
     * claim and the group membership list. Returns the group id hex.
     */
    suspend fun installSenderKeyDistribution(authenticatedSenderHex: String, distribution: ByteArray): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeInstallSenderKeyDistribution(authenticatedSenderHex, distribution)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust sender-key-install JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Rust sender-key distribution install failed")
                null
            }
        }

    /**
     * Encrypt a group message over the v3 sender-keys format (Ratchet
     * Stage 4): per-sender forward secrecy instead of the v2 shared
     * symmetric key. Dark-launched — live group traffic still rides
     * [nativeSendGroupMessage]'s v2 path until the cutover.
     */
    suspend fun encryptGroupMessageV3(groupIdHex: String, plaintext: String): ByteArray? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeEncryptGroupMessageV3(groupIdHex, plaintext)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust group-v3-encrypt JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust group v3 encryption failed")
            null
        }
    }

    /**
     * Iteration of this device's own sender chain for a group, or -1
     * when no chain exists (never sent, or wiped by a rekey). `<= 0`
     * means no member holds the current chain — [RatchetSender] uses
     * that as the fan-out-distributions-first signal.
     */
    suspend fun ownSenderChainIteration(groupIdHex: String): Long = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext -1L
        try {
            nativeOwnSenderChainIteration(groupIdHex)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust chain-iteration JNI is not linked")
            -1L
        } catch (e: Exception) {
            Timber.e(e, "Rust chain-iteration probe failed")
            -1L
        }
    }

    /**
     * Publish an already-encrypted frame on a group's gossip topic.
     * The v3 send path encrypts and publishes in two steps (unlike the
     * legacy one-shot [sendGroupMessage]) so the wire bytes can be
     * persisted for offline retry before the first publish attempt.
     */
    suspend fun publishGroupFrame(groupIdHex: String, wire: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext false
        try {
            nativePublishGroupFrame(groupIdHex, wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust group-frame-publish JNI is not linked")
            false
        } catch (e: Exception) {
            Timber.e(e, "Rust group-frame publish failed")
            false
        }
    }

    /**
     * Deterministic 16-byte id (32-char hex) of a v3 sender-key group
     * frame — the v3 analogue of [extractMessageId]. The sender stamps
     * it on the outbound row; the receiver's [publishGroupMessageAck]
     * carries the same id so the row flips to DELIVERED. Null for
     * non-v3 frames or groups whose key we don't hold.
     */
    suspend fun extractV3MessageId(wire: ByteArray): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeExtractV3MessageId(wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust v3-message-id JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust v3 message-id extraction failed")
            null
        }
    }

    /**
     * Publish a signed delivery ack for a decrypted v3 group message
     * on the group topic (the v2 path auto-acks in Rust; v3 decrypts
     * in Kotlin, so the receiver triggers the ack here). Best-effort.
     */
    suspend fun publishGroupMessageAck(groupIdHex: String, messageIdHex: String): Boolean =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext false
            try {
                nativePublishGroupMessageAck(groupIdHex, messageIdHex)
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust v3-ack JNI is not linked")
                false
            } catch (e: Exception) {
                Timber.e(e, "Rust v3 message ack failed")
                false
            }
        }

    /**
     * Build this device's signed prekey bundle and broadcast it on the
     * global topic so peers can initiate ratchet sessions with us.
     * Receivers verify + cache it Rust-side from any topic. Call after
     * the network node starts; re-publishing is idempotent (the bundle
     * is stable until its prekeys rotate).
     */
    suspend fun publishLocalPrekeyBundle(): Boolean = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext false
        try {
            val wire = nativeBuildLocalPrekeyBundle() ?: return@withContext false
            nativeSendP2PMessage("", wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust prekey-bundle JNI is not linked")
            false
        } catch (e: Exception) {
            Timber.e(e, "Prekey bundle publish failed")
            false
        }
    }

    /**
     * Decrypt an inbound v3 group frame (Ratchet Stage 4). Returns a
     * JSON string `{"groupId": hex, "senderId": hex, "plaintext": str}`
     * — the sender is authenticated by their ephemeral group signing
     * key, so members cannot impersonate each other. Null on unknown
     * group, missing distribution, forgery, or replay.
     */
    suspend fun decryptGroupMessageV3(wire: ByteArray): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeDecryptGroupMessageV3(wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust group-v3-decrypt JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust group v3 decryption failed")
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
     * Return the locally-active identity's `IdentityId` as a 64-char
     * lowercase hex string — same shape that
     * [inspectEnvelopeSender] returns for inbound envelopes, so
     * persisted `Message.senderId` rows stay interoperable across
     * send and receive paths. Distinct from [getMyFingerprint]:
     * the fingerprint is the 8-byte BLAKE3 truncation used for OOB
     * comparison; this is the full 32-byte id used as the canonical
     * sender id on the wire.
     *
     * Returns null if onboarding hasn't completed yet.
     */
    suspend fun getMyIdentityId(): String? =
        withContext(Dispatchers.IO) {
            if (!isInitialized) return@withContext null
            try {
                nativeGetMyIdentityId()
            } catch (e: UnsatisfiedLinkError) {
                Timber.e(e, "Rust my-identity-id JNI is not linked")
                null
            } catch (e: Exception) {
                Timber.e(e, "Rust my-identity-id retrieval failed")
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
     * Owner-only ownership transfer. Atomically promotes
     * `newOwnerIdHex` to `Owner` and demotes the active identity
     * (the donor) to `Admin` in one signed wire frame. Returns the
     * JSON envelope from `nativeTransferOwnership` on success, null
     * if the JNI call rejected the request (donor isn't the
     * current Owner, target isn't an active member, transferring
     * to self, …).
     */
    suspend fun transferOwnership(
        groupIdHex: String,
        newOwnerIdHex: String,
    ): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeTransferOwnership(groupIdHex, newOwnerIdHex)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust transfer-ownership JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust transfer-ownership failed")
            null
        }
    }

    /**
     * Extract the canonical 16-byte BLAKE3 message id from a
     * fresh group-message wire envelope (output of
     * `encryptGroupMessage`) as a 32-char lowercase hex string.
     * Used at send time to stamp the local Message row's `wireId`
     * column so a later inbound `onMessageAcked` can look up the
     * row and bump its delivered-ack list.
     *
     * Returns null when the bytes don't carry a group-message
     * frame (e.g. the wire is from the direct P2P path) — caller
     * persists the row without a wireId.
     */
    suspend fun extractMessageId(wire: ByteArray): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeExtractMessageId(wire)
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust extract-message-id JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust extract-message-id failed")
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

    /**
     * List every group the active identity belongs to from the
     * Rust core's local view. Returns the JSON array as-is — see
     * `com.qubee.messenger.groups.GroupSummary.listFromJson` for
     * the structured shape. Returns null if the JNI call rejected
     * the request (no active identity, group manager not
     * initialised). An empty array is a valid success — the user
     * is in zero groups.
     */
    suspend fun listGroups(): String? = withContext(Dispatchers.IO) {
        if (!isInitialized) return@withContext null
        try {
            nativeListGroups()
        } catch (e: UnsatisfiedLinkError) {
            Timber.e(e, "Rust list-groups JNI is not linked")
            null
        } catch (e: Exception) {
            Timber.e(e, "Rust list-groups failed")
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

    private external fun nativeInitialize(dataDir: String, keystorePassphrase: ByteArray): Boolean
    private external fun nativeRegisterCallback(callback: NetworkCallback)
    private external fun nativeStartNetwork(bootstrapNodes: String): Boolean
    private external fun nativeSendP2PMessage(peerId: String, data: ByteArray): Boolean

    // Direct-message/session JNI owned by Rust.
    private external fun nativeEncryptMessage(sessionId: String, plaintext: String): ByteArray?
    private external fun nativeBuildLocalPrekeyBundle(): ByteArray?
    private external fun nativeInstallPeerPrekeyBundle(bundleWire: ByteArray): String?
    private external fun nativeEncryptDirectMessage(peerIdHex: String, plaintext: String): ByteArray?
    private external fun nativeDecryptDirectMessage(wire: ByteArray): String?
    private external fun nativeInspectDirectMessageSender(wire: ByteArray): String?
    private external fun nativeCreateSenderKeyDistribution(groupIdHex: String): ByteArray?
    private external fun nativeInstallSenderKeyDistribution(authenticatedSenderHex: String, distribution: ByteArray): String?
    private external fun nativeEncryptGroupMessageV3(groupIdHex: String, plaintext: String): ByteArray?
    private external fun nativeDecryptGroupMessageV3(wire: ByteArray): String?
    private external fun nativeCreateDirectDistributionMessage(peerIdHex: String, groupIdHex: String): ByteArray?
    private external fun nativeOwnSenderChainIteration(groupIdHex: String): Long
    private external fun nativePublishGroupFrame(groupIdHex: String, wire: ByteArray): Boolean
    private external fun nativeExtractV3MessageId(wire: ByteArray): String?
    private external fun nativePublishGroupMessageAck(groupIdHex: String, messageIdHex: String): Boolean
    private external fun nativeResetGroupSenderState(groupIdHex: String): Int
    private external fun nativeResetDirectSession(peerIdHex: String): Int
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
    private external fun nativeListGroups(): String?
    private external fun nativeGetMyIdentityIdHex(): String?
    private external fun nativeGetMyIdentityId(): String?

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
    private external fun nativeTransferOwnership(
        groupIdHex: String,
        newOwnerIdHex: String,
    ): String?
    private external fun nativeExtractMessageId(wire: ByteArray): String?
    private external fun nativeSendGroupMessage(
        groupIdHex: String,
        plaintext: ByteArray,
    ): String?
    private external fun nativeResetIdentity(dataDir: String): Boolean

    external fun nativeCleanup()
}
