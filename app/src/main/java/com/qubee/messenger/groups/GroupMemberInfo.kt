package com.qubee.messenger.groups

import com.google.gson.annotations.SerializedName

/**
 * Slim Kotlin shape for a member returned from
 * `QubeeManager.listGroupMembers` / `nativeListGroupMembers`.
 *
 * Distinct from `com.qubee.messenger.data.model.Contact` — this
 * is a snapshot of the *Rust core's* view of a group's roster, not
 * a row in the local address book. The two are joined display-side
 * by matching `identityIdHex` against `Contact.identityId` so a
 * group member who's also a saved contact gets the contact's
 * display name + verified badge in the UI.
 */
data class GroupMemberInfo(
    @SerializedName("identity_id_hex") val identityIdHex: String,
    @SerializedName("display_name") val displayName: String,
    /// "Owner" / "Admin" / "Moderator" / "Member" / "Observer" /
    /// "Custom". Matches the Rust `Role` enum's variant name —
    /// rendered as-is on the UI for now.
    @SerializedName("role") val role: String,
    @SerializedName("is_active") val isActive: Boolean,
    @SerializedName("joined_at") val joinedAt: Long,
)
