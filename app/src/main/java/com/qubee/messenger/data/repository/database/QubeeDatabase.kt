package com.qubee.messenger.data.repository.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import androidx.sqlite.db.SupportSQLiteDatabase
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
    //     matching index.
    // v3: Message gained `wireId` (32-char hex of the canonical
    //     group-message id, used to look up the row when an
    //     `onMessageAcked` callback arrives) and `deliveredAckers`
    //     (JSON-encoded list of acker `IdentityId` hex values).
    // exportSchema = true generates JSON snapshots into
    // `app/schemas/<version>.json` so MigrationTestHelper can
    // validate `Migrations.kt` actually moves the schema between
    // versions correctly.
    version = 3,
    exportSchema = true,
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
                // Real migrations land in `Migrations.kt` as
                // schema bumps happen. The destructive fallback
                // stays as a safety net: any version pair
                // [ALL_MIGRATIONS] doesn't cover (e.g. someone
                // installed a debug build, force-set
                // `version = 99`, then back to current) hard-
                // resets rather than corrupting the schema.
                .addMigrations(*ALL_MIGRATIONS)
                .fallbackToDestructiveMigration()
                // Canary: SQLCipher v4 defaults (cipher_compatibility = 4,
                // cipher_page_size = 4096, HMAC-SHA512, 256k KDF iter)
                // are what we rely on for the threat model. If a future
                // sqlcipher-android upgrade silently shifts them we want
                // to crash loudly on first DB open rather than silently
                // continue with weaker settings.
                .addCallback(SqlCipherDefaultsCanary)
                .build()
        }

        private object SqlCipherDefaultsCanary : Callback() {
            override fun onOpen(db: SupportSQLiteDatabase) {
                super.onOpen(db)
                val compat = readIntPragma(db, "cipher_compatibility")
                val pageSize = readIntPragma(db, "cipher_page_size")
                if (compat != EXPECTED_CIPHER_COMPAT || pageSize != EXPECTED_PAGE_SIZE) {
                    // Throw to abort startup. The Hilt-provided database
                    // singleton will fail; the calling layer surfaces
                    // the failure to the user. Continuing under
                    // unexpected SQLCipher params would be silently
                    // weaker.
                    error(
                        "Unexpected SQLCipher params: cipher_compatibility=$compat" +
                            " (want $EXPECTED_CIPHER_COMPAT), cipher_page_size=$pageSize" +
                            " (want $EXPECTED_PAGE_SIZE)",
                    )
                }
                Timber.d(
                    "SQLCipher params OK: compat=%d page_size=%d",
                    compat,
                    pageSize,
                )
            }

            private fun readIntPragma(db: SupportSQLiteDatabase, name: String): Int =
                db.query("PRAGMA $name").use { cursor ->
                    if (cursor.moveToFirst()) cursor.getInt(0) else -1
                }
        }

        private const val EXPECTED_CIPHER_COMPAT = 4
        private const val EXPECTED_PAGE_SIZE = 4096

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
