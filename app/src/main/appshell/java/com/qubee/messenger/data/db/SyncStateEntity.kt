package com.qubee.messenger.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "sync_state")
data class SyncStateEntity(
    @PrimaryKey val id: String = RELAY_ID,
    val lastHistorySyncAt: Long,
    val lastRelaySessionId: String,
) {
    companion object {
        const val RELAY_ID = "relay"
    }
}
