package com.qubee.messenger.data.db

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [
        IdentityEntity::class,
        ConversationEntity::class,
        MessageEntity::class,
        SessionEntity::class,
        SyncStateEntity::class,
    ],
    version = 7,
    exportSchema = false,
)
abstract class QubeeDatabase : RoomDatabase() {
    abstract fun qubeeDao(): QubeeDao
}
