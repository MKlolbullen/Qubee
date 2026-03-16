package com.qubee.messenger.util

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings

object PermissionHelper {

    /**
     * Get all required permissions for the app
     */
    fun getRequiredPermissions(): List<String> {
        val permissions = mutableListOf<String>()
        
        // Core permissions
        permissions.add(Manifest.permission.INTERNET)
        permissions.add(Manifest.permission.ACCESS_NETWORK_STATE)
        permissions.add(Manifest.permission.CAMERA)
        permissions.add(Manifest.permission.RECORD_AUDIO)
        permissions.add(Manifest.permission.READ_CONTACTS)
        permissions.add(Manifest.permission.VIBRATE)
        
        // Storage permissions based on API level
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.READ_MEDIA_IMAGES)
            permissions.add(Manifest.permission.READ_MEDIA_VIDEO)
            permissions.add(Manifest.permission.READ_MEDIA_AUDIO)
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            permissions.add(Manifest.permission.READ_EXTERNAL_STORAGE)
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
                permissions.add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        }
        
        // Biometric permissions
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            permissions.add(Manifest.permission.USE_BIOMETRIC)
        } else {
            permissions.add(Manifest.permission.USE_FINGERPRINT)
        }
        
        return permissions
    }

    /**
     * Get critical permissions that are required for core functionality
     */
    fun getCriticalPermissions(): List<String> {
        return listOf(
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO
        )
    }

    /**
     * Check if a permission is critical for app functionality
     */
    fun isCriticalPermission(permission: String): Boolean {
        return getCriticalPermissions().contains(permission)
    }

    /**
     * Get optional permissions that enhance functionality but aren't critical
     */
    fun getOptionalPermissions(): List<String> {
        val allPermissions = getRequiredPermissions()
        val criticalPermissions = getCriticalPermissions()
        return allPermissions - criticalPermissions.toSet()
    }

    /**
     * Open app settings page
     */
    fun openAppSettings(context: Context) {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", context.packageName, null)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        context.startActivity(intent)
    }

    /**
     * Get permission rationale message for a specific permission
     */
    fun getPermissionRationale(permission: String): String {
        return when (permission) {
            Manifest.permission.CAMERA -> 
                "Camera permission is needed to take photos and videos for sharing."
            Manifest.permission.RECORD_AUDIO -> 
                "Microphone permission is needed to record voice messages and make calls."
            Manifest.permission.READ_CONTACTS -> 
                "Contacts permission is needed to find friends who are using the app."
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.READ_MEDIA_IMAGES,
            Manifest.permission.READ_MEDIA_VIDEO,
            Manifest.permission.READ_MEDIA_AUDIO -> 
                "Storage permission is needed to share photos, videos, and files."
            Manifest.permission.POST_NOTIFICATIONS -> 
                "Notification permission is needed to alert you about new messages."
            Manifest.permission.USE_BIOMETRIC,
            Manifest.permission.USE_FINGERPRINT -> 
                "Biometric permission is needed for secure app authentication."
            else -> "This permission is needed for the app to function properly."
        }
    }

    /**
     * Check if permission is related to storage
     */
    fun isStoragePermission(permission: String): Boolean {
        return permission in listOf(
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.READ_MEDIA_IMAGES,
            Manifest.permission.READ_MEDIA_VIDEO,
            Manifest.permission.READ_MEDIA_AUDIO
        )
    }

    /**
     * Check if permission is related to media capture
     */
    fun isMediaPermission(permission: String): Boolean {
        return permission in listOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO
        )
    }

    /**
     * Check if permission is related to notifications
     */
    fun isNotificationPermission(permission: String): Boolean {
        return permission in listOf(
            Manifest.permission.POST_NOTIFICATIONS,
            Manifest.permission.VIBRATE
        )
    }
}

