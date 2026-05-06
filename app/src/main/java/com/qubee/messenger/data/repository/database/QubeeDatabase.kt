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
import com.qubee.messenger.security.SqlCipherKeyProvider
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import timber.log.Timber

@Database(
    entities = [
        Contact::class,
        Conversation::class,
        Message::class,
        CryptoKey::class,
    ],
    // v2: Contact gained a `peerId` column (libp2p routing) and a
    // matching index. fallbackToDestructiveMigration recreates the
    // DB on the bump; pre-alpha data isn't yet meant to survive
    // schema changes.
    version = 2,
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

        @Volatile
        private var INSTANCE: QubeeDatabase? = null

        fun getInstance(context: Context, keyProvider: SqlCipherKeyProvider): QubeeDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: build(context, keyProvider).also { INSTANCE = it }
            }
        }

        private fun build(
            context: Context,
            keyProvider: SqlCipherKeyProvider,
        ): QubeeDatabase {
            // SQLCipher's native loader has to run before the first
            // connection opens. The 4.6 release moved the entry-point
            // to `net.zetetic.database.sqlcipher.SQLiteDatabase`.
            SQLiteDatabase.loadLibs(context)

            // Detect a database file written under the previous
            // hardcoded passphrase and wipe it before opening with
            // the new Keystore-derived key. Users with pre-alpha data
            // will be re-onboarded; the pre-alpha disclaimer in the
            // README has always promised this.
            wipeIfLegacy(context, keyProvider.legacyPassphrase())

            val key = keyProvider.getOrCreate()
            val factory = SupportOpenHelperFactory(key)

            return Room.databaseBuilder(
                context.applicationContext,
                QubeeDatabase::class.java,
                DATABASE_NAME,
            )
                .openHelperFactory(factory)
                // Pre-alpha: hard reset on schema change. Real
                // migrations are post-alpha.
                .fallbackToDestructiveMigration()
                .build()
        }

        /**
         * If the database file at [DATABASE_NAME] was written under
         * the legacy hardcoded passphrase, delete it (and its WAL/SHM
         * sidecars) so Room can recreate it under the new key.
         *
         * No-op when the file doesn't exist (fresh install) or when
         * the legacy passphrase doesn't open it (already migrated, or
         * a different passphrase was in use).
         */
        private fun wipeIfLegacy(context: Context, legacyPassphrase: ByteArray) {
            val dbFile = context.getDatabasePath(DATABASE_NAME)
            if (!dbFile.exists()) return

            val opensWithLegacy = try {
                SQLiteDatabase.openDatabase(
                    dbFile.absolutePath,
                    legacyPassphrase,
                    null,
                    SQLiteDatabase.OPEN_READONLY,
                ).use { /* opened cleanly — confirmed legacy */ }
                true
            } catch (e: Exception) {
                // Either the file isn't a valid SQLCipher DB, or it
                // was already opened under a different (Keystore-
                // derived) key. Either way: leave it alone.
                false
            }

            if (opensWithLegacy) {
                Timber.w("Detected legacy SQLCipher DB; wiping before reopening under Keystore-derived key.")
                SQLiteDatabase.deleteDatabase(dbFile)
            }
        }
    }
}
