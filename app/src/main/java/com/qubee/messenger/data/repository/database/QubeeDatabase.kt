package com.qubee.messenger.data.repository.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.CryptoKey
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.repository.database.dao.ContactDao
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.CryptoKeyDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

@Database(
    entities = [
        Contact::class,
        Conversation::class,
        Message::class,
        CryptoKey::class,
    ],
    version = 1,
    exportSchema = false,
)
@TypeConverters(Converters::class)
abstract class QubeeDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun cryptoKeyDao(): CryptoKeyDao

    companion object {
        private const val DATABASE_NAME = "qubee_database"

        // Pre-alpha placeholder passphrase. NOT secure on its own —
        // anyone with file-system access on a rooted device can
        // recover it from the APK. The follow-up batch wires this
        // to a key stored in the Android Keystore (or derives it
        // from the local Rust SecureKeyStore master key). See the
        // plan file's "Real SQLCipher passphrase derivation"
        // roadmap entry.
        //
        // Treat this constant as a feature flag: when the real
        // derivation lands, this falls out and the Hilt module
        // produces the byte array via Keystore directly.
        private val PRE_ALPHA_PASSPHRASE: ByteArray =
            "qubee-pre-alpha-passphrase-not-secret".toByteArray(Charsets.UTF_8)

        @Volatile
        private var INSTANCE: QubeeDatabase? = null

        fun getInstance(context: Context): QubeeDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: build(context).also { INSTANCE = it }
            }
        }

        private fun build(context: Context): QubeeDatabase {
            // SQLCipher's native loader has to run before the first
            // connection opens. The 4.6 release moved the entry-point
            // to `net.zetetic.database.sqlcipher.SQLiteDatabase`;
            // we keep the call here so callers don't accidentally
            // hit an unloaded native lib.
            net.zetetic.database.sqlcipher.SQLiteDatabase.loadLibs(context)

            val factory = SupportOpenHelperFactory(PRE_ALPHA_PASSPHRASE.copyOf())
            return Room.databaseBuilder(
                context.applicationContext,
                QubeeDatabase::class.java,
                DATABASE_NAME,
            )
                .openHelperFactory(factory)
                // Pre-alpha: hard reset on schema change. Real
                // migrations are post-alpha — see the plan file.
                .fallbackToDestructiveMigration()
                .build()
        }
    }
}
