package com.qubee.messenger.data.database

import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import android.content.Context
import com.qubee.messenger.data.database.dao.ContactDao
import com.qubee.messenger.data.database.dao.ConversationDao
import com.qubee.messenger.data.database.dao.MessageDao
import com.qubee.messenger.data.database.dao.CryptoKeyDao
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.CryptoKey

@Database(
    entities = [
        Contact::class,
        Conversation::class,
        Message::class,
        CryptoKey::class
    ],
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class QubeeDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun cryptoKeyDao(): CryptoKeyDao

    companion object {
        @Volatile
        private var INSTANCE: QubeeDatabase? = null

        fun getDatabase(context: Context): QubeeDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    QubeeDatabase::class.java,
                    "qubee_database"
                )
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}

