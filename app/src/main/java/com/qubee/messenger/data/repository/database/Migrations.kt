package com.qubee.messenger.data.repository.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * Schema migrations for [QubeeDatabase].
 *
 * Until the first stable schema (tracked for v0.2.0), the
 * [QubeeDatabase] still calls `fallbackToDestructiveMigration()`
 * as a safety net — any version pair we don't have a migration
 * for resets the local DB. This file's job is to add real
 * migrations one at a time as columns / tables change so users
 * upgrading from v0.1.x → v0.1.y keep their inbox.
 *
 * Adding a new migration:
 *   1. Bump `@Database(version = N)` in `QubeeDatabase`.
 *   2. Add a new `MIGRATION_(N-1)_N` constant below with the
 *      `ALTER TABLE` / `CREATE TABLE` / etc. it needs.
 *   3. Add it to [ALL_MIGRATIONS] so it gets registered.
 *   4. Add a unit / instrumented test that exercises the path
 *      (open at version N-1, write some rows, run migration,
 *      verify rows survive + new columns default correctly).
 *
 * SQLCipher caveat: the underlying database is SQLCipher; Room's
 * `Migration` objects run with a SQLCipher connection just like
 * regular SQLite, but raw queries via `db.execSQL` are sensitive
 * to PRAGMA changes. The `SqlCipherDefaultsCanary` callback in
 * `QubeeDatabase` runs *after* migrations, so a migration is
 * free to assume the v4 cipher_compatibility / 4096 page_size
 * defaults are in effect.
 */

/**
 * v2 → v3.
 *
 * Adds two columns to the `messages` table for delivery
 * confirmation:
 *   * `wireId TEXT` — 32-char hex of the canonical group-message
 *     id (BLAKE3 truncation; see `group_message_id` in the Rust
 *     core). Set at send time via `nativeExtractMessageId`. Null
 *     for legacy rows.
 *   * `deliveredAckers TEXT NOT NULL DEFAULT '[]'` — JSON-encoded
 *     `List<String>` of acker `IdentityId` hex values that have
 *     ack'd this outbound message. The TypeConverter on the
 *     Kotlin side decodes the empty default `'[]'` to
 *     `emptyList()`; re-encoding never produces a NULL on save,
 *     so the NOT NULL guard is safe.
 */
val MIGRATION_2_3: Migration = object : Migration(2, 3) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE messages ADD COLUMN wireId TEXT")
        db.execSQL("ALTER TABLE messages ADD COLUMN deliveredAckers TEXT NOT NULL DEFAULT '[]'")
    }
}

/**
 * Full migration set, in lexical-version order. Registered with
 * Room via `Room.databaseBuilder(...).addMigrations(*ALL_MIGRATIONS)`
 * in [QubeeDatabase.build].
 */
val ALL_MIGRATIONS: Array<Migration> = arrayOf(
    MIGRATION_2_3,
)
