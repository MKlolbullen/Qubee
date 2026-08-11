package com.qubee.messenger.calling

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
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
import com.qubee.messenger.crypto.QubeeManager
import dagger.hilt.android.AndroidEntryPoint
import timber.log.Timber
import javax.inject.Inject

/**
 * Microphone foreground service that owns the [AudioCallEngine] for the
 * lifetime of a single active call. Started by [MessageService] when the
 * call becomes Active and stopped when it returns to Idle; the mic capture
 * outlives the UI so a backgrounded call keeps talking.
 *
 * Inbound remote Opus frames arrive on the network thread (via
 * `NetworkCallback.onRemoteMedia` in MessageService) and are routed here
 * through [deliverRemoteAudio], which forwards them to the running engine
 * when the call ids agree.
 *
 * **Device-validation pending.** Like [AudioCallEngine], this is a
 * compile-verified scaffold — the microphone FGS start on API 34+, the
 * runtime `RECORD_AUDIO` grant flow, and the codec paths all need a
 * physical device to prove out.
 */
@AndroidEntryPoint
class CallMediaService : Service() {

    @Inject lateinit var qubeeManager: QubeeManager

    private var engine: AudioCallEngine? = null

    @Volatile private var activeCallIdHex: String = ""

    override fun onCreate() {
        super.onCreate()
        active = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val callIdHex = intent?.getStringExtra(EXTRA_CALL_ID)
        val peerIdHex = intent?.getStringExtra(EXTRA_PEER_ID)
        if (callIdHex.isNullOrEmpty() || peerIdHex.isNullOrEmpty()) {
            Timber.w("CallMediaService started without call/peer id; stopping")
            stopSelf()
            return START_NOT_STICKY
        }

        try {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                createNotification(),
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
                } else {
                    0
                },
            )
        } catch (e: Exception) {
            // API 31+ throws if we were started without the mic permission
            // or from a disallowed state. Fail closed — no call audio —
            // rather than crash the process.
            Timber.e(e, "startForeground(microphone) rejected; stopping call media")
            stopSelf()
            return START_NOT_STICKY
        }

        // A second invite for the same call is idempotent; a different call
        // replaces the engine (the previous call must already be tearing down).
        if (engine != null && activeCallIdHex == callIdHex) {
            return START_STICKY
        }
        engine?.stop()
        activeCallIdHex = callIdHex
        engine = AudioCallEngine(qubeeManager).apply { start(callIdHex, peerIdHex) }
        Timber.d("CallMediaService audio engine started for call %s", callIdHex)
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        engine?.stop()
        engine = null
        activeCallIdHex = ""
        if (active === this) active = null
        Timber.d("CallMediaService destroyed")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Route one remote Opus frame to the running engine, if it's this call. */
    private fun onRemoteAudio(callIdHex: String, payload: ByteArray) {
        if (callIdHex == activeCallIdHex) {
            engine?.onRemoteAudioFrame(payload)
        }
    }

    private fun createNotification(): Notification {
        val notificationManager =
            getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                QubeeApplication.NOTIFICATION_CHANNEL_SERVICE,
                getString(R.string.notification_channel_service),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
        return NotificationCompat.Builder(this, QubeeApplication.NOTIFICATION_CHANNEL_SERVICE)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Qubee call in progress")
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .build()
    }

    companion object {
        private const val NOTIFICATION_ID = 1002
        private const val EXTRA_CALL_ID = "call_id_hex"
        private const val EXTRA_PEER_ID = "peer_id_hex"

        // The single live service instance, so the network thread can push
        // remote frames without binding. Written on create/destroy on the
        // main thread; the volatile read from the network thread sees the
        // latest publish.
        @Volatile
        private var active: CallMediaService? = null

        /** Bring up mic capture + playback for [callIdHex] ↔ [peerIdHex]. */
        fun start(context: Context, callIdHex: String, peerIdHex: String) {
            val intent = Intent(context, CallMediaService::class.java).apply {
                putExtra(EXTRA_CALL_ID, callIdHex)
                putExtra(EXTRA_PEER_ID, peerIdHex)
            }
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                Timber.w(e, "Could not start CallMediaService")
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, CallMediaService::class.java))
        }

        /**
         * Forward a remote audio frame from the network callback to the live
         * engine. No-op when no call media service is running or the call id
         * doesn't match the active call.
         */
        fun deliverRemoteAudio(callIdHex: String, payload: ByteArray) {
            active?.onRemoteAudio(callIdHex, payload)
        }
    }
}
