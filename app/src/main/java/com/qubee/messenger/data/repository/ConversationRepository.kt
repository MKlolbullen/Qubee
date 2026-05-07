package com.qubee.messenger.data.repository

import com.google.gson.JsonParser
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Conversation
import com.qubee.messenger.data.model.ConversationType
import com.qubee.messenger.data.model.ConversationWithDetails
import com.qubee.messenger.data.repository.database.dao.ConversationDao
import com.qubee.messenger.data.repository.database.dao.MessageDao
import com.qubee.messenger.groups.GroupSummary
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

// Real Room-backed implementation — rev-3 priority 6, extended in
// the conv-bridge batch to mint hex-encoded Rust GroupIds for the
// `id` column. The single `id` field flows unchanged through the
// JNI sessionId parameter on `nativeEncryptMessage` /
// `nativeDecryptMessage`, so Kotlin and Rust agree on conversation
// identity without a separate translation table.
@Singleton
class ConversationRepository @Inject constructor(
    private val conversationDao: ConversationDao,
    @Suppress("unused") private val messageDao: MessageDao,
    private val qubeeManager: QubeeManager,
) {

    fun getAllConversations(): Flow<List<Conversation>> =
        conversationDao.getAllConversations()

    fun getConversationsWithDetails(): Flow<List<ConversationWithDetails>> =
        conversationDao.getConversationsWithDetails()

    fun getConversationFlow(conversationId: String): Flow<Conversation?> =
        conversationDao.getConversationFlow(conversationId)

    suspend fun getConversationById(conversationId: String): Conversation? =
        conversationDao.getConversationById(conversationId)

    /// Look up the existing direct conversation with `contactId` and
    /// return its id (the hex-encoded Rust `GroupId`), or mint a
    /// fresh one via [QubeeManager.createGroup] and persist it.
    ///
    /// The minted group has the local user as its only Rust-side
    /// member; the remote contact only becomes a Rust-side member
    /// after the existing invite + handshake flow lands them
    /// (see `nativeCreateGroupInvite` + `process_request_join`).
    /// Until then, encrypt round-trips on this conversation will
    /// return null on the decrypt side because the contact won't
    /// have the group key yet — that's the honest state to surface
    /// in UI ("waiting for invite acceptance").
    ///
    /// Returns the empty string if onboarding hasn't completed
    /// (no active identity ⇒ Rust refuses `createGroup`); callers
    /// should treat empty as "cannot send / receive yet".
    suspend fun getOrCreateConversationId(contactId: String): String {
        val existing = conversationDao.getConversationsByType(ConversationType.DIRECT)
            .firstOrNull { it.participants.contains(contactId) }
        if (existing != null) return existing.id

        val groupIdHex = mintRustGroupForDirect(contactId) ?: return ""

        val now = System.currentTimeMillis()
        val conversation = Conversation(
            id = groupIdHex,
            type = ConversationType.DIRECT,
            name = "",
            participants = listOf(contactId),
            createdAt = now,
            updatedAt = now,
        )
        conversationDao.insertConversation(conversation)
        return groupIdHex
    }

    /// Mint a fresh Rust group representing a 1:1 chat and return
    /// the hex-encoded `GroupId`. Returns null if `QubeeManager` is
    /// not yet initialised or the JSON shape is unexpected.
    ///
    /// The display-only `name` is the contact's id; the Rust core
    /// stores it inside the persistent group record but doesn't
    /// surface it on the wire.
    private suspend fun mintRustGroupForDirect(contactId: String): String? {
        val raw = qubeeManager.createGroup(name = "1:1 with $contactId") ?: return null
        return runCatching {
            JsonParser.parseString(raw).asJsonObject
                .get("group_id_hex")?.asString
                ?.takeIf { it.length == 64 } // 32 bytes hex
        }.getOrNull()
    }

    suspend fun upsertConversation(conversation: Conversation) {
        conversationDao.insertConversation(conversation)
    }

    suspend fun updateArchivedStatus(conversationId: String, archived: Boolean) {
        conversationDao.updateArchivedStatus(conversationId, archived)
    }

    suspend fun updatePinnedStatus(conversationId: String, pinned: Boolean) {
        conversationDao.updatePinnedStatus(conversationId, pinned)
    }

    suspend fun deleteConversation(conversationId: String) {
        conversationDao.deleteConversationById(conversationId)
    }

    /**
     * Fold every group the Rust core knows about into the local
     * Conversation table. Used at app cold-start so a fresh install
     * (or post-wipe re-launch) doesn't show an empty inbox while the
     * Rust core silently holds onto recovered group state.
     *
     * Behaviour:
     *  * Existing rows are preserved as-is when the Rust group is
     *    unchanged (`version <= existing.updatedAt`-derived guard
     *    isn't strict; we conservatively only refresh `name` /
     *    `updatedAt` when the Rust state is newer or the row is
     *    missing).
     *  * New rows are inserted with `type = GROUP`, `name` from the
     *    Rust core, `updatedAt = lastUpdated`, and a single-element
     *    `participants` list containing the local user — the actual
     *    member roster lives in `nativeListGroupMembers` and is
     *    fetched on-demand by the Group Details sheet, not
     *    duplicated into the Room column.
     *  * Rust groups that have a row but where we're no longer a
     *    member are *not* deleted — leaving the group keeps the
     *    history visible by design (see `ChatViewModel.leaveGroup`
     *    docstring).
     *
     * Returns the count of new rows inserted, for log/diagnostic
     * use; ignored by the caller's happy path.
     */
    suspend fun hydrateFromRustGroups(groups: List<GroupSummary>): Int {
        var inserted = 0
        for (group in groups) {
            val existing = conversationDao.getConversationById(group.groupIdHex)
            val now = System.currentTimeMillis()
            if (existing == null) {
                conversationDao.insertConversation(
                    Conversation(
                        id = group.groupIdHex,
                        type = ConversationType.GROUP,
                        name = group.name,
                        participants = emptyList(),
                        createdAt = now,
                        updatedAt = group.lastUpdated.takeIf { it > 0 } ?: now,
                    ),
                )
                inserted += 1
            } else if (existing.name != group.name && group.name.isNotBlank()) {
                conversationDao.insertConversation(
                    existing.copy(name = group.name, updatedAt = now),
                )
            }
        }
        return inserted
    }
}
