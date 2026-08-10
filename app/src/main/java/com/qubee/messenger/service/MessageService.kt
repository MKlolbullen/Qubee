package com.qubee.messenger.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.qubee.messenger.QubeeApplication
import com.qubee.messenger.R
import com.qubee.messenger.crypto.EncryptedMessage
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.MessageRepository
import com.qubee.messenger.network.NetworkCallback
import com.qubee.messenger.ui.main.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import timber.log.Timber
import java.util.UUID
import javax.inject.Inject

// Foreground service that keeps the libp2p node alive while the app
// is backgrounded AND routes inbound encrypted messages through the
// JNI bridge into the local message store.
//
// Caveat on senderId routing: libp2p hands us a libp2p PeerId
// string, not an application-level contactId. Today they get
// treated as the same thing — getOrCreateConversationId on a fresh
// peerId will mint a new direct conversation row. A real PeerId →
// contactId mapping table is post-alpha work. Until then, a peer
// the user has *already* paired with via the invite/handshake flow
// will hash to a stable conversationId; a stranger's first packet
// also gets a row, but the decrypt will fail (no shared group key)
// so the row never grows beyond the empty case.
@AndroidEntryPoint
class MessageService : Service(), NetworkCallback {

    @Inject lateinit var qubeeManager: QubeeManager
    @Inject lateinit var messageRepository: MessageRepository
    @Inject lateinit var conversationRepository: ConversationRepository
    @Inject lateinit var contactRepository: ContactRepository
    @Inject lateinit var ratchetSender: com.qubee.messenger.crypto.RatchetSender

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    // Network callbacks launch concurrently. Stripe by exact direct wire id so
    // duplicates of one ciphertext cannot race the read -> ratchet-encrypt ->
    // receipt-cache sequence, while keeping memory bounded under hostile input.
    private val directFrameLocks = Array(DIRECT_FRAME_LOCK_STRIPES) { Mutex() }
    private var isRunning = false

    companion object {
        private const val NOTIFICATION_ID = 1001
        /// "QUBEE_DMS\x02" — current PQXDH + Double Ratchet frame magic.
        private val DIRECT_V2_MAGIC: ByteArray =
            "QUBEE_DMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x02)
        /// "QUBEE_GMS\x03" — the Stage 4 sender-keys group frame magic.
        /// Kept in sync with MAGIC_GROUP_MESSAGE_V3 in
        /// src/ratchet/sender_keys.rs (pinned in wire_stability).
        private val GROUP_V3_MAGIC: ByteArray =
            "QUBEE_GMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x03)

        /// "QUBEE_GMS\x05" — the keyed-selector sender-keys frame (v5,
        /// metadata parity with the sealed v4 envelope). Same decrypt
        /// entry point Rust-side; recognised on receive before any
        /// sender emits it. Kept in sync with MAGIC_GROUP_MESSAGE_V5.
        private val GROUP_V5_MAGIC: ByteArray =
            "QUBEE_GMS".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x05)
        /// How often the retry loop wakes up to scan the DB. Cheap
        /// query (indexed on `status` already, `nextRetryAt`
        /// filtering is in-memory across the small SENT set); 30s
        /// matches the shortest backoff so a freshly-scheduled
        /// retry isn't slept past.
        private const val RETRY_LOOP_INTERVAL_MS: Long = 30_000L
        /// Bounded retry budget per outbound row. Five attempts
        /// across the documented backoff schedule (30s, 2m, 10m,
        /// 30m, 2h) = ~3 hours of attempts before the row is left
        /// alone.
        private const val OFFLINE_RETRY_MAX_ATTEMPTS: Int = 5
        private const val DIRECT_FRAME_LOCK_STRIPES: Int = 64

        /// Prekey bundles ride gossipsub, so peers offline at publish
        /// time miss them and can never initiate v3 toward us. A
        /// periodic republish bounds that window; the bundle is
        /// stable between prekey rotations, so re-broadcasts are
        /// idempotent on the receiving side.
        private const val PREKEY_REPUBLISH_INTERVAL_MS: Long = 30L * 60 * 1000
        /// Soft cap on rows processed per tick to keep the DB scan
        /// cheap even with a large backlog.
        private const val RETRY_BATCH_LIMIT: Int = 32

        /**
         * Start the P2P foreground service. Must be called from a
         * foreground context (Activity onStart/onResume) — on API 31+
         * `startForegroundService` from the background throws
         * `ForegroundServiceStartNotAllowedException`. We swallow that
         * here so a mistimed call degrades to "service not started"
         * rather than crashing the app; the service is retried on the
         * next foreground entry.
         */
        fun start(context: Context) {
            try {
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, MessageService::class.java),
                )
            } catch (e: Exception) {
                Timber.w(e, "Could not start MessageService (background start?)")
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, MessageService::class.java))
        }
    }

    override fun onCreate() {
        super.onCreate()
        Timber.d("MessageService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            try {
                // Explicitly bind the foreground-service type. On API
                // 34+ a FGS started without the matching type (or
                // without the FOREGROUND_SERVICE_CONNECTED_DEVICE
                // permission) is rejected; ServiceCompat picks the
                // right startForeground overload per API level. The
                // manifest also declares the type as a belt-and-braces.
                // NOTE: a network-only connectedDevice FGS needs
                // on-device validation (some OEMs expect a companion-
                // device association); confirm start on API 34 during
                // the two-device hardware test.
                ServiceCompat.startForeground(
                    this,
                    NOTIFICATION_ID,
                    createServiceNotification(),
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        // connectedDevice: a long-lived P2P link, not a
                        // time-boxed sync. Avoids the Android-14 dataSync
                        // ~6h/day cap that would force-stop the node.
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    } else {
                        0
                    },
                )
                startP2PNetwork()
                startOfflineRetryLoop()
                startPrekeyRepublishLoop()
                isRunning = true
                Timber.d("MessageService started")
            } catch (e: Exception) {
                // API 31+ throws ForegroundServiceStartNotAllowedException
                // if we were started from the background without an
                // exemption. Don't crash the process — stop cleanly;
                // MainActivity restarts the service next time it's
                // foregrounded. (Caught as Exception because the
                // specific type is API-31-only and we compile against
                // minSdk 24.)
                Timber.e(e, "startForeground rejected; stopping service")
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    private fun startP2PNetwork() {
        serviceScope.launch {
            if (qubeeManager.initialize()) {
                qubeeManager.setNetworkCallback(this@MessageService)
                if (qubeeManager.startNetworkNode()) {
                    Timber.d("P2P Network Node started successfully")
                    // Announce our signed prekey bundle so peers can
                    // open forward-secret sessions with us (Ratchet
                    // Stage 5). Best-effort: peers who miss it get it
                    // on our next service start; without it they
                    // simply can't initiate v3 and their sends fail
                    // closed on their side.
                    if (!qubeeManager.publishLocalPrekeyBundle()) {
                        Timber.w("Prekey bundle publish failed — peers cannot initiate ratchet sessions")
                    }
                } else {
                    Timber.e("Failed to start P2P Network Node")
                }
            }
        }
    }

    /**
     * Periodic re-publish of outbound messages whose recipients
     * haven't yet ack'd. Re-uses the original `wireBytes` so the
     * row's `wireId` stays stable and any late ack still correlates
     * via `MessageRepository.applyAck`.
     *
     * Retry budget: [OFFLINE_RETRY_MAX_ATTEMPTS] attempts with the
     * back-off schedule in [retryBackoffMs] (30s, 2m, 10m, 30m, 2h —
     * roughly three hours total). After the budget is hit `nextRetryAt`
     * is cleared, the row stays `SENT` indefinitely, and the user
     * can manually resend.
     *
     * Group caveat: ack arrival flips status to `DELIVERED` on the
     * FIRST ack. So a group with 4 active members but only one online
     * is treated as delivered after the one online member acks — the
     * other three are still missing. Tracking per-recipient delivery
     * (and per-recipient retry) needs full membership awareness on
     * the sender side, which is a separate batch. For v0.1.x the
     * documented behaviour is "delivered once at least one peer
     * acks".
     */
    private fun startOfflineRetryLoop() {
        serviceScope.launch {
            // Crash-consistency recovery, run once before the retry loop.
            // A row still in PREPARED at process start was orphaned by a
            // previous death between the PREPARED write and encrypt/queue;
            // surface it as FAILED (text preserved, resendable) so it's
            // never silently lost. Rows that already reached SENDING/SENT
            // carry their ciphertext and are re-driven by the tick below.
            try {
                val failed = messageRepository.recoverStalePreparedOutbound()
                if (failed > 0) {
                    Timber.i("crash recovery: %d stale PREPARED row(s) marked FAILED", failed)
                }
                // Transmit-window recovery: a row orphaned in SENDING has
                // durable ciphertext but an unconfirmed publish; promote it
                // to SENT so the retry loop below reclaims it instead of
                // leaving it queued forever.
                val requeued = messageRepository.recoverOrphanedSendingOutbound()
                if (requeued > 0) {
                    Timber.i("crash recovery: %d orphaned SENDING row(s) requeued for retry", requeued)
                }
            } catch (e: Exception) {
                Timber.w(e, "outbound crash recovery failed")
            }
            while (isActive) {
                kotlinx.coroutines.delay(RETRY_LOOP_INTERVAL_MS)
                try {
                    runOfflineRetryTick()
                } catch (e: Exception) {
                    Timber.w(e, "offline retry tick failed")
                }
            }
        }
    }

    /**
     * Periodic re-broadcast of the local prekey bundle (see
     * [PREKEY_REPUBLISH_INTERVAL_MS]). Complements the publish-on-
     * network-start in [startP2PNetwork] so peers who were offline
     * then still get the bundle within one interval of coming online.
     */
    private fun startPrekeyRepublishLoop() {
        serviceScope.launch {
            while (isActive) {
                kotlinx.coroutines.delay(PREKEY_REPUBLISH_INTERVAL_MS)
                try {
                    if (!qubeeManager.publishLocalPrekeyBundle()) {
                        Timber.w("Periodic prekey bundle republish failed")
                    }
                } catch (e: Exception) {
                    Timber.w(e, "prekey republish tick failed")
                }
            }
        }
    }

    private suspend fun runOfflineRetryTick() {
        // Retry any sender-key distributions still owed to members we
        // couldn't reach before (their prekey bundle may have since
        // arrived). Cheap no-op when the ratchet flag is off or nothing
        // is pending; a full bundle-install callback is a later refinement.
        runCatching { ratchetSender.redeliverPending() }
            .onFailure { Timber.w(it, "pending-distribution redelivery failed") }

        val now = System.currentTimeMillis()
        val due = messageRepository.dueForRetry(now, OFFLINE_RETRY_MAX_ATTEMPTS, RETRY_BATCH_LIMIT)
        if (due.isEmpty()) return
        Timber.d("offline retry tick: %d row(s) due", due.size)
        for (row in due) {
            val wire = row.wireBytes ?: continue
            // v3 group frames belong on their group's topic — the
            // row's conversationId IS the group id hex on that path.
            // Everything else re-publishes exactly as it was sent.
            val ok = runCatching {
                if (isGroupV3Frame(wire) || isGroupV5Frame(wire)) {
                    qubeeManager.publishGroupFrame(row.conversationId, wire)
                } else {
                    qubeeManager.sendP2PMessage(row.senderId, wire)
                }
            }.getOrDefault(false)
            val nextAttempt = row.retryAttempt + 1
            val nextRetry = if (!ok || nextAttempt < OFFLINE_RETRY_MAX_ATTEMPTS) {
                now + retryBackoffMs(nextAttempt)
            } else {
                null // budget exhausted; stop retrying
            }
            messageRepository.scheduleNextRetry(row.id, nextAttempt, nextRetry)
            Timber.d(
                "retried %s (attempt %d, ok=%s, next=%s)",
                row.id, nextAttempt, ok, nextRetry,
            )
        }
    }

    /** Exponential back-off in milliseconds, indexed by 1-based attempt. */
    private fun retryBackoffMs(attempt: Int): Long = when (attempt) {
        1 -> 30_000L         // 30s
        2 -> 2L * 60_000L    // 2m
        3 -> 10L * 60_000L   // 10m
        4 -> 30L * 60_000L   // 30m
        else -> 2L * 3_600_000L  // 2h thereafter (caller bounds to budget)
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        serviceScope.cancel()
        Timber.d("MessageService destroyed")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onMessageReceived(senderId: String, data: ByteArray) {
        Timber.d("Encrypted message received from %s (%d bytes)", senderId, data.size)
        serviceScope.launch {
            try {
                // Ratchet wire formats first (Stage 5 receive side).
                // Receivers must understand the new frames before any
                // sender starts emitting them, so this runs regardless
                // of the send-side rollout flag; until peers upgrade
                // and flip their flag, no frame matches and the legacy
                // path below is untouched.
                if (handleRatchetFrame(senderId, data)) {
                    return@launch
                }
                // Resolve the application-level contact id, if any,
                // by libp2p PeerId. If the lookup misses,
                // `populateContactPeerId` below tries to link the
                // libp2p PeerId to a Contact known by `identityId`
                // by reading the wire envelope's signed sender_id
                // field — that's the missing link between the two
                // identity spaces (libp2p PeerId vs application
                // IdentityId), exposed by
                // `qubeeManager.inspectEnvelopeSender`.
                // Group gossip publishing is Anonymous, so a gossip-
                // delivered frame arrives with an EMPTY senderId (the
                // transport can no longer tell us the author's PeerId).
                // Route such frames by the envelope's *authenticated*
                // sender_id instead, and never stamp/trust the (unknown)
                // gossip peer. A non-empty senderId only comes from the
                // authenticated direct channel, where PeerId linkage is
                // sound.
                val authenticatedPeer = senderId.isNotEmpty()
                // For anonymous gossip we route by the envelope's
                // authenticated sender_id. Inspecting it crosses the JNI
                // boundary and re-parses the envelope, so do it once and
                // reuse for both the contact lookup and the routing
                // fallback.
                val envelopeIdentity =
                    if (authenticatedPeer) null else qubeeManager.inspectEnvelopeSender(data)
                var mappedContact =
                    if (authenticatedPeer) {
                        contactRepository.getContactByPeerId(senderId)
                    } else {
                        envelopeIdentity?.let { contactRepository.getContactByIdentityId(it) }
                    }
                val routedSenderId = mappedContact?.id
                    ?: if (authenticatedPeer) senderId else envelopeIdentity
                if (routedSenderId.isNullOrEmpty()) {
                    Timber.w("Cannot route inbound: no authenticated sender (anonymous gossip, unknown identity)")
                    return@launch
                }
                val conversationId = conversationRepository.getOrCreateConversationId(routedSenderId)
                if (conversationId.isEmpty()) {
                    Timber.w(
                        "Cannot route inbound from %s: conversation setup failed (onboarding?)",
                        routedSenderId,
                    )
                    return@launch
                }
                // EncryptedMessage::fromBytes wraps the raw bytes as
                // its `ciphertext` field; the round-trip back through
                // toBytes() preserves the wire envelope unchanged
                // (header/iv/mac default to empty in the rev-3
                // EncryptedMessage shape — see crypto/EncryptedPayloads.kt).
                val envelope = EncryptedMessage.fromBytes(data)
                if (envelope == null) {
                    Timber.w("Empty payload from %s", senderId)
                    return@launch
                }

                // Try to populate Contact.peerId from the wire
                // envelope's authenticated `sender_id` field. Best-
                // effort — failure (no matching contact, malformed
                // envelope, etc.) leaves the routing fallback in
                // place and processing continues. Only when the peer
                // itself is authenticated (direct channel): under
                // Anonymous gossip the peer is unknown, and stamping an
                // empty PeerId would corrupt the PeerId<->IdentityId
                // trust linkage (and could spuriously trip KeyChanged).
                if (mappedContact == null && authenticatedPeer) {
                    mappedContact = populateContactPeerId(senderId, data)
                }

                val plaintext = qubeeManager.decryptMessage(conversationId, envelope)
                if (plaintext == null) {
                    Timber.w(
                        "Decrypt failed for inbound from %s in conversation %s",
                        senderId,
                        conversationId,
                    )
                    return@launch
                }
                val finalRoutedSenderId = mappedContact?.id ?: routedSenderId
                val msg = Message(
                    id = UUID.randomUUID().toString(),
                    conversationId = conversationId,
                    senderId = finalRoutedSenderId,
                    content = plaintext,
                    contentType = MessageType.TEXT,
                    timestamp = System.currentTimeMillis(),
                    status = MessageStatus.DELIVERED,
                    isFromMe = false,
                )
                messageRepository.saveMessage(msg)
                if (mappedContact != null) {
                    val now = System.currentTimeMillis()
                    contactRepository.updateOnlineStatus(mappedContact.id, true, now)
                }
            } catch (e: Exception) {
                Timber.e(e, "Failed to process inbound message from %s", senderId)
            }
        }
    }

    /**
     * Persist a group message that the Rust core has already
     * verified (sender is an active member, hybrid signature
     * passes, generation counter matches) and AEAD-decrypted.
     *
     * The Conversation row is keyed directly by `groupIdHex` —
     * matches what `ConversationRepository.hydrateFromRustGroups`
     * inserts on cold start and what
     * `GroupInviteViewModel.persistGroupConversation` writes on
     * create / accept. If no row exists yet (e.g., a state-sync
     * landed a group we don't know about because hydration hasn't
     * run), we conservatively *insert* a placeholder row so the
     * inbound message has somewhere to land — better than
     * dropping the decrypted plaintext on the floor.
     *
     * Sender mapping mirrors the direct path: try
     * `getContactByIdentityId(senderIdHex)` for a friendly display
     * name, fall back to the raw hex senderId so the row is at
     * least decryptable in the UI ("Unknown 4f7e…").
     *
     * Best-effort throughout — a failure anywhere logs and drops
     * the message rather than crashing the foreground service.
     */
    override fun onGroupMessageReceived(
        groupIdHex: String,
        senderIdHex: String,
        plaintext: ByteArray,
        timestampSeconds: Long,
    ) {
        Timber.d(
            "Group message received: group=%s sender=%s (%d bytes)",
            groupIdHex,
            senderIdHex,
            plaintext.size,
        )
        serviceScope.launch {
            try {
                persistInboundGroupMessage(
                    groupIdHex = groupIdHex,
                    senderIdHex = senderIdHex,
                    content = plaintext.toString(Charsets.UTF_8),
                    timestampMillis = timestampSeconds * 1_000L,
                )
            } catch (e: Exception) {
                Timber.e(
                    e,
                    "Failed to persist group message: group=%s sender=%s",
                    groupIdHex,
                    senderIdHex,
                )
            }
        }
    }

    /**
     * Shared persistence for inbound group messages — used by both the
     * v2 callback above and the v3 sender-keys receive path. Mints a
     * placeholder Conversation row when hydration hasn't caught up,
     * mirrors the sender mapping of the direct path.
     */
    private suspend fun persistInboundGroupMessage(
        groupIdHex: String,
        senderIdHex: String,
        content: String,
        timestampMillis: Long,
    ) {
        val existing = conversationRepository.getConversationById(groupIdHex)
        if (existing == null) {
            conversationRepository.upsertConversation(
                com.qubee.messenger.data.model.Conversation(
                    id = groupIdHex,
                    type = com.qubee.messenger.data.model.ConversationType.GROUP,
                    name = "",
                    participants = emptyList(),
                    createdAt = System.currentTimeMillis(),
                    updatedAt = System.currentTimeMillis(),
                ),
            )
        }
        val matched = contactRepository.getContactByIdentityId(senderIdHex)
        val resolvedSenderId = matched?.id ?: senderIdHex
        val msg = Message(
            id = UUID.randomUUID().toString(),
            conversationId = groupIdHex,
            senderId = resolvedSenderId,
            content = content,
            contentType = MessageType.TEXT,
            timestamp = timestampMillis,
            status = MessageStatus.DELIVERED,
            isFromMe = false,
        )
        messageRepository.saveMessage(msg)
        if (matched != null) {
            contactRepository.updateOnlineStatus(matched.id, true, System.currentTimeMillis())
        }
    }

    /**
     * Recognise + process the Stage 5 ratchet wire formats. Returns
     * true when the frame was a ratchet frame (handled or dropped),
     * false to fall through to the legacy path.
     *
     * Decrypt failures return true with a log — a frame carrying a
     * ratchet magic must never fall into the legacy decrypt, where a
     * misleading failure would surface.
     */
    private suspend fun handleRatchetFrame(peerId: String, data: ByteArray): Boolean {
        // 1:1 PQXDH + Double Ratchet frame (QUBEE_DMS). Detect by magic,
        // not by sender resolution: an unknown/tampered selector is still a
        // direct frame and must fail closed here rather than reach legacy decrypt.
        if (isDirectV2Frame(data)) {
            val directMessageId = qubeeManager.extractDirectMessageId(data)
            if (directMessageId == null) {
                Timber.w("Malformed QUBEE_DMS frame from %s", peerId)
                return true
            }

            val lockIndex = Math.floorMod(directMessageId.hashCode(), directFrameLocks.size)
            return directFrameLocks[lockIndex].withLock {
                // Lost-receipt recovery: retries deliberately reuse the exact wire
                // bytes, while the Double Ratchet correctly rejects decrypting the
                // same frame twice. Persisting the inbound wireId lets us recognise
                // an already-accepted frame and issue a fresh encrypted receipt
                // without weakening ratchet replay protection. This survives a
                // process death because the evidence is in Room, not a RAM cache.
                val prior = messageRepository.getActiveInboundMessageByWireId(directMessageId)
                if (prior != null) {
                    sendOrReplayDirectDeliveryAck(
                        inboundMessage = prior,
                        originalWire = data,
                        messageIdHex = directMessageId,
                        authenticatedSenderIdentityHex = null,
                    )
                    return@withLock true
                }

                val resultJson = qubeeManager.decryptDirectMessage(data)
                if (resultJson == null) {
                    Timber.w("Ratchet 1:1 decrypt failed from %s", peerId)
                    return@withLock true
                }
                val result = JSONObject(resultJson)
                val senderIdentityHex = result.optString("senderId")
                when (result.optString("kind")) {
                    "text" -> {
                        // Same peer↔identity linkage as the legacy path,
                        // but from the channel-authenticated sender rather
                        // than an envelope field — the trust policy still
                        // sees every (peerId, identityId) observation.
                        // Only observe the PeerId<->IdentityId linkage when the
                        // peer is authenticated (direct channel). Anonymous
                        // gossip delivers an empty peerId; feeding that to the
                        // trust policy would stamp an empty PeerId and could
                        // spuriously trip KeyChanged. Fall back to identity-only
                        // resolution in that case.
                        val contact =
                            if (peerId.isNotEmpty()) {
                                contactRepository.observePeerIdentityLink(peerId, senderIdentityHex)
                            } else {
                                contactRepository.getContactByIdentityId(senderIdentityHex)
                            }
                        val routedSenderId = contact?.id ?: senderIdentityHex
                        val conversationId =
                            conversationRepository.getOrCreateConversationId(routedSenderId)
                        if (conversationId.isEmpty()) {
                            Timber.w("Cannot route ratchet 1:1 from %s", senderIdentityHex)
                            return@withLock true
                        }
                        val inboundMessage = Message(
                            id = UUID.randomUUID().toString(),
                            conversationId = conversationId,
                            senderId = routedSenderId,
                            content = result.optString("text"),
                            contentType = MessageType.TEXT,
                            timestamp = System.currentTimeMillis(),
                            status = MessageStatus.DELIVERED,
                            isFromMe = false,
                            wireId = directMessageId,
                        )
                        messageRepository.saveMessage(inboundMessage)
                        if (contact != null) {
                            contactRepository.updateOnlineStatus(
                                contact.id,
                                true,
                                System.currentTimeMillis(),
                            )
                        }
                        // Receipt only after the plaintext is durably persisted. Cache
                        // the exact encrypted receipt before transmit; if it is lost, an
                        // exact text retry re-sends the same receipt bytes without advancing
                        // our send ratchet a second time.
                        sendOrReplayDirectDeliveryAck(
                            inboundMessage = inboundMessage,
                            originalWire = data,
                            messageIdHex = directMessageId,
                            authenticatedSenderIdentityHex = senderIdentityHex,
                        )
                    }
                    "ack" -> {
                        val ackedWireId = result.optString("messageId")
                        if (ackedWireId.isBlank()) {
                            Timber.w("Ratchet direct ack from %s has no message id", senderIdentityHex)
                        } else {
                            val contact = contactRepository.getContactByIdentityId(senderIdentityHex)
                            val participantId = contact?.id ?: senderIdentityHex
                            val directConversationId =
                                conversationRepository.findDirectConversationId(participantId)
                            if (directConversationId == null) {
                                Timber.w(
                                    "Ignored direct ack from %s: no matching direct conversation",
                                    senderIdentityHex,
                                )
                            } else {
                                val applied = messageRepository.applyAck(
                                    ackedWireId,
                                    senderIdentityHex,
                                    directConversationId,
                                )
                                if (!applied) {
                                    Timber.d(
                                        "Ignored direct ack for wireId=%s outside conversation=%s",
                                        ackedWireId,
                                        directConversationId,
                                    )
                                }
                            }
                        }
                        // Never ack an ack: that would create an infinite receipt loop.
                    }
                    "senderKeyDistribution" -> {
                        // Rust has already membership-checked + installed it.
                        Timber.i(
                            "Installed sender key for group %s from %s",
                            result.optString("groupId"),
                            senderIdentityHex,
                        )
                    }
                    else -> Timber.w("Unknown ratchet payload kind from %s", senderIdentityHex)
                }
                return@withLock true
            }
        }

        // Sender-keys group frame: v3 (QUBEE_GMS\x03, plaintext group
        // id) or v5 (QUBEE_GMS\x05, keyed selector). One decrypt entry
        // point — Rust routes by magic internally.
        if (isGroupV3Frame(data) || isGroupV5Frame(data)) {
            val resultJson = qubeeManager.decryptGroupMessageV3(data)
            if (resultJson == null) {
                Timber.w("Ratchet group decrypt failed (peer %s)", peerId)
                return true
            }
            val result = JSONObject(resultJson)
            val groupIdHex = result.optString("groupId")
            persistInboundGroupMessage(
                groupIdHex = groupIdHex,
                senderIdHex = result.optString("senderId"),
                content = result.optString("plaintext"),
                timestampMillis = System.currentTimeMillis(),
            )
            // Delivery ack: v2 auto-acks in Rust, but v3 decrypts here,
            // so publish the signed MessageAck for this frame's id. The
            // sender stamped the same id as the row's wireId, so its
            // onMessageAcked → applyAck flips the row to DELIVERED.
            // Best-effort: a dropped ack just leaves the sender at SENT.
            val v3MessageId = qubeeManager.extractV3MessageId(data)
            if (v3MessageId != null) {
                qubeeManager.publishGroupMessageAck(groupIdHex, v3MessageId)
            }
            return true
        }

        return false
    }

    private suspend fun sendOrReplayDirectDeliveryAck(
        inboundMessage: Message,
        originalWire: ByteArray,
        messageIdHex: String,
        authenticatedSenderIdentityHex: String?,
    ) {
        var ackWire = inboundMessage.wireBytes
        if (ackWire == null) {
            // Normal first delivery already has an authenticated sender from the
            // successful decrypt. The duplicate-after-crash path may only have the
            // durable original wire, so resolve its opaque sender selector against
            // Rust's signature-verified peer cache.
            val recipientIdentityHex = authenticatedSenderIdentityHex
                ?.takeIf { it.isNotBlank() }
                ?: qubeeManager.inspectDirectMessageSender(originalWire)
            if (recipientIdentityHex.isNullOrBlank()) {
                Timber.w("Cannot create direct receipt: sender selector is unresolved")
                return
            }
            ackWire = qubeeManager.createDirectMessageAck(recipientIdentityHex, messageIdHex)
            if (ackWire == null) {
                Timber.w("Could not create direct delivery ack for %s", messageIdHex)
                return
            }
            // Persist before transmit. A crash or an active replay after this point
            // can only cause this exact receipt ciphertext to be re-published; it
            // cannot repeatedly advance our Double Ratchet send chain.
            if (!messageRepository.cacheInboundDirectReceipt(inboundMessage.id, ackWire)) {
                val persisted = messageRepository
                    .getActiveInboundMessageByWireId(messageIdHex)
                    ?.wireBytes
                if (persisted == null) {
                    Timber.w(
                        "Direct receipt cache lost CAS for %s without a live cached row; dropping send",
                        messageIdHex,
                    )
                    return
                }
                ackWire = persisted
            }
        }

        // Rust owns QUBEE_DMS routing from the frame's opaque recipient selector.
        // Empty compatibility hint makes that authority explicit.
        if (!qubeeManager.sendP2PMessage("", ackWire)) {
            Timber.d("Direct delivery ack enqueue failed for %s; exact-text retry can replay it", messageIdHex)
        }
    }

    private fun isDirectV2Frame(data: ByteArray): Boolean {
        if (data.size < DIRECT_V2_MAGIC.size) return false
        for (i in DIRECT_V2_MAGIC.indices) {
            if (data[i] != DIRECT_V2_MAGIC[i]) return false
        }
        return true
    }

    private fun isGroupV3Frame(data: ByteArray): Boolean = hasMagic(data, GROUP_V3_MAGIC)

    private fun isGroupV5Frame(data: ByteArray): Boolean = hasMagic(data, GROUP_V5_MAGIC)

    private fun hasMagic(data: ByteArray, magic: ByteArray): Boolean {
        if (data.size < magic.size) return false
        for (i in magic.indices) {
            if (data[i] != magic[i]) return false
        }
        return true
    }

    /**
     * Inspect the wire envelope to extract the signed sender
     * `IdentityId`, look up the matching Contact, and stamp its
     * `peerId` with the libp2p sender id. Returns the linked
     * Contact on success, or null if no link could be made (e.g.
     * the sender isn't a known contact yet, or the envelope
     * doesn't parse).
     *
     * The actual write goes through ContactRepository.observePeerIdentityLink so the trust policy
     * can downgrade a previously verified contact if the same peer suddenly maps to a different
     * Qubee identity.
     */
    private suspend fun populateContactPeerId(senderPeerId: String, wire: ByteArray): com.qubee.messenger.data.model.Contact? {
        val senderIdentityHex = qubeeManager.inspectEnvelopeSender(wire) ?: return null
        val contact = contactRepository.observePeerIdentityLink(senderPeerId, senderIdentityHex) ?: run {
            Timber.d(
                "No Contact for identityId=%s; skipping peerId population for %s",
                senderIdentityHex,
                senderPeerId,
            )
            return null
        }
        Timber.d(
            "Observed Contact[id=%s, identityId=%s, trust=%s] for libp2p peer %s",
            contact.id,
            contact.identityId,
            contact.trustLevel,
            senderPeerId,
        )
        return contact
    }

    override fun onPeerDiscovered(peerId: String) {
        Timber.d("Discovered new peer: %s", peerId)
    }

    override fun onMessageAcked(
        groupIdHex: String,
        messageIdHex: String,
        ackerIdHex: String,
        timestampSeconds: Long,
    ) {
        Timber.d(
            "MessageAck received: group=%s message=%s acker=%s",
            groupIdHex,
            messageIdHex,
            ackerIdHex,
        )
        serviceScope.launch {
            try {
                val applied = messageRepository.applyAck(
                    messageIdHex,
                    ackerIdHex,
                    groupIdHex,
                )
                if (!applied) {
                    Timber.d(
                        "Ignored ack for wireId=%s outside group=%s",
                        messageIdHex,
                        groupIdHex,
                    )
                }
            } catch (e: Exception) {
                Timber.e(
                    e,
                    "Failed to apply ack: group=%s message=%s acker=%s",
                    groupIdHex,
                    messageIdHex,
                    ackerIdHex,
                )
            }
        }
    }

    override fun onPeerLinked(peerId: String, identityIdHex: String) {
        Timber.d("Linking peer %s ↔ identity %s", peerId, identityIdHex)
        serviceScope.launch {
            try {
                val contact = contactRepository.observePeerIdentityLink(peerId, identityIdHex)
                if (contact == null) {
                    Timber.d(
                        "onPeerLinked: no Contact for identityId=%s; skipping peerId stamp",
                        identityIdHex,
                    )
                    return@launch
                }
                Timber.d(
                    "onPeerLinked: Contact[id=%s, identityId=%s, trust=%s] linked to peer %s",
                    contact.id,
                    contact.identityId,
                    contact.trustLevel,
                    peerId,
                )
            } catch (e: Exception) {
                Timber.e(e, "onPeerLinked failed for identity=%s", identityIdHex)
            }
        }
    }

    private fun createServiceNotification(): Notification {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                QubeeApplication.NOTIFICATION_CHANNEL_SERVICE,
                getString(R.string.notification_channel_service),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.notification_channel_service_description)
                enableVibration(false)
                enableLights(false)
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, QubeeApplication.NOTIFICATION_CHANNEL_SERVICE)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Qubee P2P Node Active")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }
}
