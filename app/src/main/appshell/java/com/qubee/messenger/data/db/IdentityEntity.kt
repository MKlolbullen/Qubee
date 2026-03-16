package com.qubee.messenger.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "identity")
data class IdentityEntity(
    @PrimaryKey val id: String = SELF_ID,
    val displayName: String,
    val deviceLabel: String,
    val identityFingerprint: String,
    val publicBundleBase64: String,
    val identityBundleBase64: String,
    val relayHandle: String,
    val deviceId: String,
    val nativeBacked: Boolean,
    val createdAt: Long,
) {
    companion object {
        const val SELF_ID = "self"
    }
}
