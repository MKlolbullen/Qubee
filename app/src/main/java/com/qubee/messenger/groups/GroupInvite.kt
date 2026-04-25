package com.qubee.messenger.groups

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.google.gson.annotations.SerializedName

/**
 * Hard cap mirrored from `QUBEE_MAX_GROUP_MEMBERS` in the Rust core.
 * Kept here so UI can render member-count limits without a JNI hop.
 */
const val QUBEE_MAX_GROUP_MEMBERS = 16

/**
 * Result of parsing a `qubee://invite/<token>` deep link.
 */
data class GroupInvite(
    @SerializedName("group_id_hex") val groupIdHex: String,
    @SerializedName("group_name") val groupName: String,
    @SerializedName("inviter_id_hex") val inviterIdHex: String,
    @SerializedName("inviter_name") val inviterName: String,
    @SerializedName("invitation_code") val invitationCode: String,
    @SerializedName("expires_at") val expiresAt: Long? = null,
    @SerializedName("max_members") val maxMembers: Int = QUBEE_MAX_GROUP_MEMBERS,
) {
    val isExpired: Boolean
        get() {
            val expiry = expiresAt ?: return false
            return expiry < System.currentTimeMillis() / 1000L
        }

    companion object {
        private val gson = Gson()

        fun fromJson(json: String?): GroupInvite? {
            if (json.isNullOrBlank()) return null
            return try {
                gson.fromJson(json, GroupInvite::class.java)
            } catch (e: JsonSyntaxException) {
                null
            }
        }
    }
}

/**
 * JSON descriptor shipped to the Rust core when building a fresh invite link.
 */
data class GroupInviteRequest(
    @SerializedName("group_id_hex") val groupIdHex: String,
    @SerializedName("group_name") val groupName: String,
    @SerializedName("inviter_id_hex") val inviterIdHex: String,
    @SerializedName("inviter_name") val inviterName: String,
    @SerializedName("invitation_code") val invitationCode: String,
    @SerializedName("expires_at") val expiresAt: Long? = null,
) {
    fun toJson(): String = Gson().toJson(this)
}

/**
 * Response shape returned from `nativeBuildInviteLink`. Mirrors the JSON
 * built in `jni_api.rs::Java_..._nativeBuildInviteLink`.
 */
data class BuildInviteResponse(
    @SerializedName("link") val link: String,
    @SerializedName("max_members") val maxMembers: Int = QUBEE_MAX_GROUP_MEMBERS,
) {
    companion object {
        private val gson = Gson()

        fun fromJson(json: String?): BuildInviteResponse? {
            if (json.isNullOrBlank()) return null
            return try {
                gson.fromJson(json, BuildInviteResponse::class.java)
            } catch (e: JsonSyntaxException) {
                null
            }
        }
    }
}
