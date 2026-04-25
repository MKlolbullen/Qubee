package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.groups.AcceptInviteResult
import com.qubee.messenger.groups.BuildInviteResponse
import com.qubee.messenger.groups.CreatedGroup
import com.qubee.messenger.groups.CreatedInvite
import com.qubee.messenger.groups.GroupInvite
import com.qubee.messenger.groups.GroupInviteRequest
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
