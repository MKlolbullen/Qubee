package com.qubee.messenger.data.db

import android.content.Context
import androidx.room.Room
import com.qubee.messenger.security.DatabasePassphraseManager
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

object SecureDatabaseFactory {
    fun build(context: Context, passphraseManager: DatabasePassphraseManager): QubeeDatabase {
        val passphraseChars = passphraseManager.getOrCreatePassphrase()
        val passphraseBytes = SQLiteDatabase.getBytes(passphraseChars)
        passphraseChars.fill('\u0000')

        val factory = SupportFactory(passphraseBytes, null, true)
        return Room.databaseBuilder(context.applicationContext, QubeeDatabase::class.java, "qubee.db")
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration()
            .build()
    }
}
