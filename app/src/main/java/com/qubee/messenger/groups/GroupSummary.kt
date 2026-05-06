package com.qubee.messenger.groups

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken

/**
 * Slim Kotlin shape for a group returned from
 * `QubeeManager.listGroups` / `nativeListGroups`.
 *
 * Used at app cold-start to hydrate the local Conversation table
 * from the Rust core's view: when the SQLCipher DB is empty
 * (fresh install or after a wipe) but the Rust core has groups
 * recovered from `nativeInitialize`, the inbox would otherwise
 * appear empty even though group keys + membership are intact.
 *
 * Distinct from `data.model.Conversation` — this is a Rust
 * snapshot, not a Room row. Hydration logic in
 * `ConversationRepository` joins the two by `groupIdHex`.
 */
data class GroupSummary(
    @SerializedName("group_id_hex") val groupIdHex: String,
    @SerializedName("name") val name: String,
    @SerializedName("member_count") val memberCount: Int,
    /// "Owner" / "Admin" / "Moderator" / "Member" / "Observer" /
    /// "Custom". Mirrors the small fixed vocabulary used by
    /// `GroupMemberInfo.role`.
    @SerializedName("my_role") val myRole: String,
    @SerializedName("last_updated") val lastUpdated: Long,
    @SerializedName("version") val version: Long,
) {
    companion object {
        /**
         * Decode the JSON array returned by
         * `QubeeManager.listGroups`. Returns an empty list on
         * malformed input — the caller treats "no groups" and
         * "couldn't decode" identically (the inbox renders empty
         * either way).
         */
        fun listFromJson(json: String): List<GroupSummary> = runCatching {
            val type = object : TypeToken<List<GroupSummary>>() {}.type
            Gson().fromJson<List<GroupSummary>>(json, type) ?: emptyList()
        }.getOrDefault(emptyList())
    }
}
