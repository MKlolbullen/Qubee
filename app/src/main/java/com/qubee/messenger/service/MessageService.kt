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
import com.qubee.messenger.data.repository.MessageRepository
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.ui.main.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import timber.log.Timber
import javax.inject.Inject

@AndroidEntryPoint
class MessageService : Service() {

    @Inject
    lateinit var messageRepository: MessageRepository
    
    @Inject
    lateinit var conversationRepository: ConversationRepository
    
    @Inject
    lateinit var contactRepository: ContactRepository

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
            isRunning = true
            Timber.d("MessageService started")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        serviceScope.cancel()
        Timber.d("MessageService destroyed")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startForegroundService() {
        val notification = createServiceNotification()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun createServiceNotification(): Notification {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create notification channel for Android O and above
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

        // Create intent to open main activity
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, QubeeApplication.NOTIFICATION_CHANNEL_SERVICE)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Secure messaging service running")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun startBackgroundTasks() {
        // Start periodic cleanup task
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

        // Start message processing task
        serviceScope.launch {
            while (isActive && isRunning) {
                try {
                    processIncomingMessages()
                    delay(5000) // Check for new messages every 5 seconds
                } catch (e: Exception) {
                    Timber.e(e, "Error processing incoming messages")
                    delay(5000)
                }
            }
        }

        // Start disappearing message cleanup task
        serviceScope.launch {
            while (isActive && isRunning) {
                try {
                    cleanupDisappearingMessages()
                    delay(30000) // Check every 30 seconds
                } catch (e: Exception) {
                    Timber.e(e, "Error cleaning up disappearing messages")
                    delay(30000)
                }
            }
        }
    }

    private suspend fun performPeriodicCleanup() {
        try {
            // Clean up expired messages
            val expiredCount = messageRepository.cleanupExpiredMessages().getOrDefault(0)
            if (expiredCount > 0) {
                Timber.d("Cleaned up $expiredCount expired messages")
            }

            // Additional cleanup tasks can be added here
            // - Clean up old temporary files
            // - Clean up old crypto keys
            // - Optimize database
            
        } catch (e: Exception) {
            Timber.e(e, "Error in periodic cleanup")
        }
    }

    private suspend fun processIncomingMessages() {
        try {
            // This would handle incoming messages from the network
            // For now, this is a placeholder - actual implementation would depend on
            // the networking layer and message protocol
            
            // Example: Check for pending messages, decrypt them, and store in database
            // processPendingNetworkMessages()
            
        } catch (e: Exception) {
            Timber.e(e, "Error processing incoming messages")
        }
    }

    private suspend fun cleanupDisappearingMessages() {
        try {
            val result = messageRepository.cleanupExpiredMessages()
            result.onSuccess { count ->
                if (count > 0) {
                    Timber.d("Cleaned up $count disappearing messages")
                }
            }.onFailure { error ->
                Timber.e(error, "Failed to cleanup disappearing messages")
            }
        } catch (e: Exception) {
            Timber.e(e, "Error in disappearing message cleanup")
        }
    }

    private suspend fun showMessageNotification(
        conversationId: String,
        senderName: String,
        messageContent: String
    ) {
        try {
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

            // Create intent to open conversation
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
                .setContentText(messageContent)
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
            val unreadCount = messageRepository.getTotalUnreadMessageCount()
            // Update app badge with unread count
            // This would depend on the launcher and badge implementation
        } catch (e: Exception) {
            Timber.e(e, "Failed to update unread badge")
        }
    }
}

