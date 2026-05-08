package com.qubee.messenger.data.repository.database

import android.content.ContentValues
import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Verifies the `MIGRATION_2_3` path preserves existing `messages`
 * rows when adding the `wireId` + `deliveredAckers` columns.
 *
 * Uses Room's `MigrationTestHelper` which re-runs the schema at the
 * specified version, lets us write raw `ContentValues`, then runs
 * the migration and re-opens with the post-migration entity
 * definition.
 *
 * Note: this test does **not** exercise SQLCipher — `MigrationTestHelper`
 * uses the framework SQLite open helper. The migration logic is the
 * same regardless; the SQLCipher layer doesn't intercept `ALTER TABLE`.
 * The `SqlCipherKeyProviderTest` exercises the encrypted-storage path
 * separately.
 *
 * Skipped under JVM `./gradlew test` because Room schema artifacts
 * aren't generated for the unit-test JVM target. Runs as part of
 * `./gradlew :app:connectedDebugAndroidTest` via the
 * `instrumented-tests.yml` workflow.
 */
@RunWith(AndroidJUnit4::class)
class MigrationsInstrumentedTest {

    @get:Rule
    val helper: MigrationTestHelper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        QubeeDatabase::class.java,
        emptyList(),
        FrameworkSQLiteOpenHelperFactory(),
    )

    @Test
    fun migrate_2_to_3_preserves_existing_messages() {
        // Open at the v2 schema and seed a row.
        helper.createDatabase(TEST_DB, 2).use { db ->
            val values = ContentValues().apply {
                put("id", "row-pre-migration")
                put("conversationId", "g1")
                put("senderId", "alice")
                put("content", "hello from v2")
                put("contentType", "TEXT")
                put("timestamp", 1_000_000L)
                put("status", "SENT")
                put("isFromMe", 1)
                put("reactions", "{}")
                put("isDeleted", 0)
                // Embedded ContactMetadata defaults — these
                // don't actually live on Message but Room's
                // strict-NOT-NULL columns sometimes need a
                // sentinel. Insert minimum required by the v2
                // schema; if the test fails on a constraint,
                // fix the column list rather than relaxing
                // the assertion.
            }
            db.insert("messages", android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE, values)
        }

        // Run the migration.
        helper.runMigrationsAndValidate(
            TEST_DB,
            3,
            true,
            MIGRATION_2_3,
        ).use { db ->
            // Existing row survives with NULL wireId + default '[]'
            // for deliveredAckers.
            db.query("SELECT id, content, wireId, deliveredAckers FROM messages WHERE id = ?", arrayOf<Any>("row-pre-migration")).use { cursor ->
                assertTrue("row survived migration", cursor.moveToFirst())
                assertEquals("hello from v2", cursor.getString(cursor.getColumnIndexOrThrow("content")))
                val wireIdIdx = cursor.getColumnIndexOrThrow("wireId")
                assertTrue(
                    "wireId is NULL on legacy rows",
                    cursor.isNull(wireIdIdx),
                )
                assertEquals(
                    "deliveredAckers default is '[]' (empty list JSON)",
                    "[]",
                    cursor.getString(cursor.getColumnIndexOrThrow("deliveredAckers")),
                )
            }
        }

        // Re-open via the production builder so the entity / DAO
        // surface sees the migrated schema. Catches the case where
        // the migration ALTER drifts from the entity definition
        // (e.g. column name typo).
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val realDb = Room.databaseBuilder(context, QubeeDatabase::class.java, TEST_DB)
            .addMigrations(MIGRATION_2_3)
            .build()
        try {
            val survived = kotlinx.coroutines.runBlocking {
                realDb.messageDao().getMessageById("row-pre-migration")
            }
            assertNotNull(survived)
            assertEquals("hello from v2", survived!!.content)
            assertNull("legacy row has no wireId", survived.wireId)
            assertEquals(emptyList<String>(), survived.deliveredAckers)
        } finally {
            realDb.close()
        }
    }

    companion object {
        private const val TEST_DB = "qubee_migration_test"
    }
}
