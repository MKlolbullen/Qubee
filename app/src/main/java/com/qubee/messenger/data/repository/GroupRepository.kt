package com.qubee.messenger.data.repository

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.groups.AcceptInviteResult
import com.qubee.messenger.groups.BuildInviteResponse
import com.qubee.messenger.groups.CreatedGroup
import com.qubee.messenger.groups.CreatedInvite
import com.qubee.messenger.groups.GroupInvite
import com.qubee.messenger.groups.GroupInviteRequest
import com.qubee.messenger.groups.GroupMemberInfo
import com.qubee.messenger.groups.QUBEE_MAX_GROUP_MEMBERS
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Thin coordinator over the Rust JNI for group invitation flows.
 *
 * Group state itself (members, messages, etc.) lives in the Rust core
 * and is reflected back via [QubeeManager]; this repository handles only
 * the small surface needed by the invite-link / QR scan UI today.
 */
@Singleton
class GroupRepository @Inject constructor(
    private val qubeeManager: QubeeManager,
) {

    /** Hard upper bound (creator + 15 invitees). Mirrors Rust core. */
    val maxMembers: Int get() = QUBEE_MAX_GROUP_MEMBERS

    /**
     * Build a `qubee://invite/<token>` deep link describing the given
     * invitation. The link is short enough to render as a QR code and to
     * paste into another messenger / SMS.
     */
    suspend fun buildInviteLink(request: GroupInviteRequest): String? = withContext(Dispatchers.IO) {
        val json = qubeeManager.buildInviteLink(request.toJson())
        BuildInviteResponse.fromJson(json)?.link
    }

    /**
     * Parse a Qubee invite link back into structured form. Returns null
     * if the link is malformed or has been tampered with.
     */
    suspend fun parseInviteLink(link: String): GroupInvite? = withContext(Dispatchers.IO) {
        val json = qubeeManager.parseInviteLink(link) ?: return@withContext null
        GroupInvite.fromJson(json)
    }

    /**
     * Record acceptance of a scanned/pasted invite link and (best-effort)
     * publish a signed `RequestJoin` over gossipsub. Returns the
     * structured outcome — including whether the network handshake
     * actually went out — or null if the JNI rejected the link.
     */
    suspend fun acceptInvite(link: String): AcceptInviteResult? = withContext(Dispatchers.IO) {
        val json = qubeeManager.acceptInvite(link) ?: return@withContext null
        AcceptInviteResult.fromJson(json)
    }

    /**
     * Create a new group owned by the active local identity. Returns the
     * created group's id + owner so the UI can immediately follow up
     * with [createInvite] and render a QR code.
     */
    suspend fun createGroup(name: String, description: String = ""): CreatedGroup? =
        withContext(Dispatchers.IO) {
            val json = qubeeManager.createGroup(name, description) ?: return@withContext null
            CreatedGroup.fromJson(json)
        }

    /**
     * The locally-active identity's `IdentityId` as a 64-char hex
     * string. Cached after first successful read. Used by the Group
     * Details sheet's "you" badge and the "Leave group" action.
     */
    suspend fun myIdentityIdHex(): String? = qubeeManager.getMyIdentityIdHex()

    /**
     * Remove a member (or yourself, for "Leave group") from a
     * group. Owner-only Rust-side; non-owner callers get a JNI
     * error which surfaces here as a null return.
     *
     * Returns the JSON envelope from `nativeRemoveMember`
     * unchanged for now — callers that just need success/failure
     * can `!= null` it; the structured shape lands when there's a
     * UI surface that uses the rotation details.
     */
    suspend fun removeMember(
        groupIdHex: String,
        memberIdHex: String,
        reason: String = "",
    ): String? = qubeeManager.removeMember(groupIdHex, memberIdHex, reason)

    /**
     * Promote (or demote) a member to a new role. Owner-only Rust-
     * side; non-owner callers get a null return. `newRole` must be
     * one of `Owner`, `Admin`, `Moderator`, `Member`, `Observer`
     * (case-insensitive Rust-side); anything else is rejected.
     *
     * Returns the JSON envelope from `nativePromoteMember`
     * unchanged for now — callers that just need success/failure
     * can `!= null` it; the structured shape (new_version,
     * network_published) lands when there's a UI surface that
     * wants those details.
     */
    suspend fun promoteMember(
        groupIdHex: String,
        memberIdHex: String,
        newRole: String,
    ): String? = qubeeManager.promoteMember(groupIdHex, memberIdHex, newRole)

    /**
     * List the active + removed members of a group from the Rust
     * core's local view. Returns null if the group isn't yet known
     * locally (e.g., the user accepted an invite but the handshake
     * confirmation hasn't landed). Callers render a "loading" or
     * "not yet" state in that case.
     */
    suspend fun listGroupMembers(groupIdHex: String): List<GroupMemberInfo>? =
        withContext(Dispatchers.IO) {
            val json = qubeeManager.listGroupMembers(groupIdHex) ?: return@withContext null
            runCatching {
                val gson = Gson()
                val type = object : TypeToken<List<GroupMemberInfo>>() {}.type
                gson.fromJson<List<GroupMemberInfo>>(json, type) ?: emptyList()
            }.getOrNull()
        }

    /**
     * Mint an invitation for a group we own. `expiresAtSeconds` /
     * `maxUses` accept negatives to mean "no limit".
     */
    suspend fun createInvite(
        groupIdHex: String,
        expiresAtSeconds: Long = -1L,
        maxUses: Int = -1,
    ): CreatedInvite? = withContext(Dispatchers.IO) {
        val json = qubeeManager.createGroupInvite(groupIdHex, expiresAtSeconds, maxUses)
            ?: return@withContext null
        CreatedInvite.fromJson(json)
    }
}
