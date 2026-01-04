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
import com.qubee.messenger.R
import com.qubee.messenger.QubeeApplication
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.MessageRepository
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.network.NetworkCallback
import com.qubee.messenger.ui.main.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import timber.log.Timber
import javax.inject.Inject

@AndroidEntryPoint
class MessageService : Service(), NetworkCallback {

    @Inject
    lateinit var messageRepository: MessageRepository
    
    @Inject
    lateinit var conversationRepository: ConversationRepository
    
    @Inject
    lateinit var contactRepository: ContactRepository

    @Inject
    lateinit var qubeeManager: QubeeManager

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var isRunning = false

    companion object {
        private const val NOTIFICATION_ID = 1001
        private const val CLEANUP_INTERVAL_MS = 60_000L // 1 minute
        
        fun start(context: Context) {
            val intent = Intent(context, MessageService::class.java)
            ContextCompat.startForegroundService(context, intent)
        }
        
        fun stop(context: Context) {
            val intent = Intent(context, MessageService::class.java)
            context.stopService(intent)
        }
    }

    override fun onCreate() {
        super.onCreate()
        Timber.d("MessageService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning) {
            startForegroundService()
            startBackgroundTasks()
            
            // Initialize P2P Network
            startP2PNetwork()
            
            isRunning = true
            Timber.d("MessageService started")
        }
        return START_STICKY
    }

    private fun startP2PNetwork() {
        serviceScope.launch {
            if (qubeeManager.initialize()) {
                // Register this service to receive Rust callbacks
                qubeeManager.setNetworkCallback(this@MessageService)
                
                // Boot up the libp2p node
                // You can pass bootstrap nodes here if you have them, e.g., "/ip4/1.2.3.4/tcp/4001/p2p/Qm..."
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
        // Optional: qubeeManager.cleanup() if you want to kill the node on service stop
        serviceScope.cancel()
        Timber.d("MessageService destroyed")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // --- NetworkCallback Implementation ---

    override fun onMessageReceived(senderId: String, data: ByteArray) {
        serviceScope.launch {
            try {
                Timber.d("Encrypted message received from $senderId (${data.size} bytes)")

                // 1. Identify or Create Session
                // In a real scenario, you'd look up the session based on the senderId
                val sessionId = "session_$senderId" // Simplified for demo

                // 2. Decrypt Payload using Rust
                // Assuming 'data' is the raw encrypted bytes. If you have a specific wrapper, adjust here.
                // We use a dummy encrypted object wrapper for the API call
                val dummyEncryptedObj = com.qubee.messenger.crypto.EncryptedMessage(
                    header = byteArrayOf(), 
                    ciphertext = data,
                    iv = byteArrayOf(),
                    mac = byteArrayOf()
                )
                
                // This will call into Rust to decrypt using the Double Ratchet
                val decryptedText = qubeeManager.decryptMessage(sessionId, dummyEncryptedObj)

                if (decryptedText != null) {
                    // 3. Save to Local Database
                    // Ensure you have a contact/conversation for this sender
                    val conversationId = conversationRepository.getOrCreateConversationId(senderId)
                    messageRepository.saveMessage(
                        sessionId = sessionId,
                        content = decryptedText,
                        isFromMe = false
                    )

                    // 4. Notify User
                    val senderName = contactRepository.getContactName(senderId) ?: "Unknown User"
                    showMessageNotification(conversationId, senderName, "New secure message")
                    updateUnreadBadge()
                } else {
                    Timber.w("Failed to decrypt message from $senderId")
                }
            } catch (e: Exception) {
                Timber.e(e, "Error processing incoming P2P message")
            }
        }
    }

    override fun onPeerDiscovered(peerId: String) {
        serviceScope.launch {
            Timber.d("Discovered new peer: $peerId")
            // Update contact status to 'Online' or similar
            // contactRepository.updateStatus(peerId, Status.ONLINE)
        }
    }

    // --- Standard Service Methods ---

    private fun startForegroundService() {
        val notification = createServiceNotification()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun createServiceNotification(): Notification {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                QubeeApplication.NOTIFICATION_CHANNEL_SERVICE,
                getString(R.string.notification_channel_service),
                NotificationManager.IMPORTANCE_LOW
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
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
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

    private fun startBackgroundTasks() {
        serviceScope.launch {
            while (isActive && isRunning) {
                try {
                    performPeriodicCleanup()
                    delay(CLEANUP_INTERVAL_MS)
                } catch (e: Exception) {
                    Timber.e(e, "Error in periodic cleanup")
                    delay(CLEANUP_INTERVAL_MS)
                }
            }
        }
    }

    private suspend fun performPeriodicCleanup() {
        try {
            val expiredCount = messageRepository.cleanupExpiredMessages().getOrDefault(0)
            if (expiredCount > 0) {
                Timber.d("Cleaned up $expiredCount expired messages")
            }
        } catch (e: Exception) {
            Timber.e(e, "Error in periodic cleanup")
        }
    }

    private fun showMessageNotification(
        conversationId: String,
        senderName: String,
        messageContent: String
    ) {
        try {
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            
            // Channel needs to be created if not exists (usually in Application class, but safety check here)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (notificationManager.getNotificationChannel(QubeeApplication.NOTIFICATION_CHANNEL_MESSAGES) == null) {
                    val channel = NotificationChannel(
                        QubeeApplication.NOTIFICATION_CHANNEL_MESSAGES,
                        "Messages",
                        NotificationManager.IMPORTANCE_HIGH
                    )
                    notificationManager.createNotificationChannel(channel)
                }
            }

            val intent = Intent(this, MainActivity::class.java).apply {
                putExtra("conversation_id", conversationId)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            }
            val pendingIntent = PendingIntent.getActivity(
                this, conversationId.hashCode(), intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val notification = NotificationCompat.Builder(this, QubeeApplication.NOTIFICATION_CHANNEL_MESSAGES)
                .setContentTitle(senderName)
                .setContentText(messageContent) // In a privacy mode, this might hide actual content
                .setSmallIcon(R.drawable.ic_notification)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()

            notificationManager.notify(conversationId.hashCode(), notification)
        } catch (e: Exception) {
            Timber.e(e, "Failed to show message notification")
        }
    }

    private suspend fun updateUnreadBadge() {
        try {
            // val unreadCount = messageRepository.getTotalUnreadMessageCount()
            // Implementation depends on launcher support
        } catch (e: Exception) {
            Timber.e(e, "Failed to update unread badge")
        }
    }
}
