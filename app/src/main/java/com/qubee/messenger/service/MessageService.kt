package com.qubee.messenger.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.qubee.messenger.QubeeApplication
import com.qubee.messenger.R
import com.qubee.messenger.crypto.EncryptedMessage
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.MessageRepository
import com.qubee.messenger.network.NetworkCallback
import com.qubee.messenger.ui.main.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
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

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isRunning = false

    companion object {
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, MessageService::class.java))
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
            startForeground(NOTIFICATION_ID, createServiceNotification())
            startP2PNetwork()
            isRunning = true
            Timber.d("MessageService started")
        }
        return START_STICKY
    }

    private fun startP2PNetwork() {
        serviceScope.launch {
            if (qubeeManager.initialize()) {
                qubeeManager.setNetworkCallback(this@MessageService)
                if (qubeeManager.startNetworkNode()) {
                    Timber.d("P2P Network Node started successfully")
                } else {
                    Timber.e("Failed to start P2P Network Node")
                }
            }
        }
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
                // Resolve the application-level contact id, if any,
                // by libp2p PeerId. If the lookup misses,
                // `populateContactPeerId` below tries to link the
                // libp2p PeerId to a Contact known by `identityId`
                // by reading the wire envelope's signed sender_id
                // field — that's the missing link between the two
                // identity spaces (libp2p PeerId vs application
                // IdentityId), exposed by
                // `qubeeManager.inspectEnvelopeSender`.
                var mappedContact = contactRepository.getContactByPeerId(senderId)
                val routedSenderId = mappedContact?.id ?: senderId
                val conversationId = conversationRepository.getOrCreateConversationId(routedSenderId)
                if (conversationId.isEmpty()) {
                    Timber.w(
                        "Cannot route inbound from %s: conversation setup failed (onboarding?)",
                        senderId,
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
                // place and processing continues.
                if (mappedContact == null) {
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
     * Inspect the wire envelope to extract the signed sender
     * `IdentityId`, look up the matching Contact, and stamp its
     * `peerId` with the libp2p sender id. Returns the linked
     * Contact on success, or null if no link could be made (e.g.
     * the sender isn't a known contact yet, or the envelope
     * doesn't parse).
     *
     * No-op if the matched Contact already has a non-null peerId
     * — matching the existing routing without re-stamping. The
     * `Index(value = ["peerId"])` on the Contact entity keeps the
     * lookup cheap.
     */
    private suspend fun populateContactPeerId(senderPeerId: String, wire: ByteArray): com.qubee.messenger.data.model.Contact? {
        val senderIdentityHex = qubeeManager.inspectEnvelopeSender(wire) ?: return null
        val contact = contactRepository.getContactByIdentityId(senderIdentityHex) ?: run {
            Timber.d(
                "No Contact for identityId=%s; skipping peerId population for %s",
                senderIdentityHex,
                senderPeerId,
            )
            return null
        }
        if (contact.peerId == senderPeerId) return contact
        contactRepository.updatePeerId(contact.id, senderPeerId)
        Timber.d(
            "Linked Contact[id=%s, identityId=%s] to libp2p peer %s",
            contact.id,
            contact.identityId,
            senderPeerId,
        )
        return contact.copy(peerId = senderPeerId)
    }

    override fun onPeerDiscovered(peerId: String) {
        Timber.d("Discovered new peer: %s", peerId)
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
