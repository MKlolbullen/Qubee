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

/**
 * Result of [com.qubee.messenger.crypto.QubeeManager.acceptInvite] /
 * [com.qubee.messenger.data.repository.GroupRepository.acceptInvite].
 *
 * `accepted_pending_network` means we wrote the receipt locally but
 * couldn't reach the inviter yet — the dispatcher will resend on the
 * next accept attempt, or the inviter will pick us up the next time
 * we publish on the gossipsub topic.
 *
 * `accepted_handshake_sent` means a signed RequestJoin was published;
 * the inviter's reply will arrive asynchronously and confirm
 * membership.
 */
/** Result of [com.qubee.messenger.data.repository.GroupRepository.createGroup]. */
data class CreatedGroup(
    @SerializedName("group_id_hex") val groupIdHex: String,
    @SerializedName("name") val name: String,
    @SerializedName("owner_id_hex") val ownerIdHex: String,
) {
    companion object {
        private val gson = Gson()
        fun fromJson(json: String?): CreatedGroup? {
            if (json.isNullOrBlank()) return null
            return try {
                gson.fromJson(json, CreatedGroup::class.java)
            } catch (e: JsonSyntaxException) {
                null
            }
        }
    }
}

/**
 * Result of [com.qubee.messenger.data.repository.GroupRepository.createInvite].
 * Carries both the QR-friendly deep link and the metadata the UI needs
 * to render an invite preview.
 */
data class CreatedInvite(
    @SerializedName("link") val link: String,
    @SerializedName("group_id_hex") val groupIdHex: String,
    @SerializedName("group_name") val groupName: String,
    @SerializedName("inviter_id_hex") val inviterIdHex: String,
    @SerializedName("inviter_name") val inviterName: String,
    @SerializedName("invitation_code") val invitationCode: String,
    @SerializedName("expires_at") val expiresAt: Long? = null,
    @SerializedName("max_members") val maxMembers: Int = QUBEE_MAX_GROUP_MEMBERS,
) {
    companion object {
        private val gson = Gson()
        fun fromJson(json: String?): CreatedInvite? {
            if (json.isNullOrBlank()) return null
            return try {
                gson.fromJson(json, CreatedInvite::class.java)
            } catch (e: JsonSyntaxException) {
                null
            }
        }
    }
}

data class AcceptInviteResult(
    @SerializedName("group_id_hex") val groupIdHex: String,
    @SerializedName("group_name") val groupName: String,
    @SerializedName("inviter_id_hex") val inviterIdHex: String,
    @SerializedName("inviter_name") val inviterName: String,
    @SerializedName("max_members") val maxMembers: Int = QUBEE_MAX_GROUP_MEMBERS,
    @SerializedName("status") val status: String = STATUS_PENDING,
    @SerializedName("network_published") val networkPublished: Boolean = false,
) {
    val isPendingNetwork: Boolean get() = status == STATUS_PENDING

    companion object {
        const val STATUS_PENDING = "accepted_pending_network"
        const val STATUS_HANDSHAKE_SENT = "accepted_handshake_sent"

        private val gson = Gson()

        fun fromJson(json: String?): AcceptInviteResult? {
            if (json.isNullOrBlank()) return null
            return try {
                gson.fromJson(json, AcceptInviteResult::class.java)
            } catch (e: JsonSyntaxException) {
                null
            }
        }
    }
}
