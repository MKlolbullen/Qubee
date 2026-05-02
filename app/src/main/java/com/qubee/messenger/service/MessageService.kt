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
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.network.NetworkCallback
import com.qubee.messenger.ui.main.MainActivity
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

// Foreground service that keeps the libp2p node alive while the app is
// backgrounded. The original version also wrote inbound messages to a
// MessageRepository / ContactRepository / ConversationRepository — that
// path was wired against types that don't exist yet (see plan A4) and
// has been pulled out. The service now logs callbacks and lets the
// in-process listeners (ChatViewModel etc.) handle UI updates once
// they're actually wired to QubeeManager.

@AndroidEntryPoint
class MessageService : Service(), NetworkCallback {

    @Inject lateinit var qubeeManager: QubeeManager

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
