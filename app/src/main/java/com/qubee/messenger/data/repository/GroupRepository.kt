package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.groups.BuildInviteResponse
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
}
