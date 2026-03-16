package com.qubee.messenger.security

import android.content.Context
import androidx.work.WorkManager
import com.qubee.messenger.crypto.QubeeManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object KillSwitch {
    suspend fun execute(context: Context) = withContext(Dispatchers.IO) {
        runCatching { WorkManager.getInstance(context).cancelAllWork() }
        runCatching { context.deleteDatabase("qubee.db") }
        runCatching { DatabasePassphraseManager(context, AppKeyManager(context)).wipe() }
        runCatching { AppKeyManager(context).deleteMasterKey() }
        runCatching { QubeeManager.cleanup() }
        runCatching {
            context.getSharedPreferences("qubee_secure_storage", Context.MODE_PRIVATE).edit().clear().apply()
        }
    }
}
