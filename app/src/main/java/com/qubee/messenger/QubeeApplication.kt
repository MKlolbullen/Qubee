package com.qubee.messenger

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.core.content.ContextCompat
import dagger.hilt.android.HiltAndroidApp
import timber.log.Timber

@HiltAndroidApp
class QubeeApplication : Application() {

    companion object {
        const val NOTIFICATION_CHANNEL_MESSAGES = "messages"
        const val NOTIFICATION_CHANNEL_CALLS = "calls"
        const val NOTIFICATION_CHANNEL_SERVICE = "service"
        
        // Load native library
        init {
            System.loadLibrary("qubee_native")
        }
    }

    override fun onCreate() {
        super.onCreate()
        
        // Initialize logging
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        
        // Create notification channels
        createNotificationChannels()
        
        // Initialize Qubee native library
        initializeQubeeLibrary()
        
        Timber.d("QubeeApplication initialized")
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = ContextCompat.getSystemService(
                this,
                NotificationManager::class.java
            ) as NotificationManager

            // Messages channel
            val messagesChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_MESSAGES,
                getString(R.string.notification_channel_messages),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.notification_channel_messages_description)
                enableVibration(true)
                enableLights(true)
            }

            // Calls channel
            val callsChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_CALLS,
                getString(R.string.notification_channel_calls),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.notification_channel_calls_description)
                enableVibration(true)
                enableLights(true)
            }

            // Service channel
            val serviceChannel = NotificationChannel(
                NOTIFICATION_CHANNEL_SERVICE,
                getString(R.string.notification_channel_service),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_service_description)
                enableVibration(false)
                enableLights(false)
            }

            notificationManager.createNotificationChannels(
                listOf(messagesChannel, callsChannel, serviceChannel)
            )
        }
    }

    private fun initializeQubeeLibrary() {
        try {
            // Initialize the native Qubee library
            val result = nativeInitialize()
            if (result) {
                Timber.d("Qubee native library initialized successfully")
            } else {
                Timber.e("Failed to initialize Qubee native library")
            }
        } catch (e: Exception) {
            Timber.e(e, "Error initializing Qubee native library")
        }
    }

    // Native method declarations
    private external fun nativeInitialize(): Boolean
}

