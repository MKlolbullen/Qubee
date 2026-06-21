package com.qubee.messenger.ui.chat

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qubee.messenger.groups.GroupMemberInfo
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeeStatusPill

/**
 * Bottom sheet variant of `ConversationDetailsSheet` for groups.
 * Shows the group's name + status pill at the top, then the
 * member roster fetched from the Rust core via
 * `ChatViewModel.loadGroupMembers()`.
 *
 * The roster loads lazily on sheet open: a `LaunchedEffect`
 * triggers `onLoadMembers` once per appearance. While the load
 * is in flight `members == null` and a spinner renders; an empty
 * list (group not yet known Rust-side, or roster genuinely
 * empty) gets the explicit "no members yet" copy instead.
 *
 * Not yet wired:
 *   * "Add member" — needs a `nativeCreateGroupInvite` call
 *     producing a fresh share link.
 *   * "Remove member" / "Promote" — need owner-role gates and
 *     existing JNI exports (`nativeRemoveMember`) /
 *     a missing one (`nativePromoteMember`).
 *   * "Leave group" — needs `nativeRemoveMember(self_id)` plus a
 *     confirm dialog.
 *
 * For now this sheet is read-only; actions land in the next
 * batch.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupDetailsSheet(
    groupName: String,
    members: List<GroupMemberInfo>?,
    myIdentityIdHex: String?,
    onLoadMembers: () -> Unit,
    onAddMember: () -> Unit,
    onRemoveMember: (memberIdHex: String) -> Unit,
    onPromoteMember: (memberIdHex: String, newRole: String) -> Unit,
    onTransferOwnership: (memberIdHex: String) -> Unit,
    onLeaveGroup: () -> Unit,
    onDismiss: () -> Unit,
) {
    val myRole = members.orEmpty()
        .firstOrNull { myIdentityIdHex != null && it.identityIdHex == myIdentityIdHex }
        ?.role
    val canManage = myRole?.let { it == "Owner" || it == "Admin" } == true
    // Promote / demote is strictly owner-only Rust-side
    // (`GroupManager::promote_member` checks `promoter.role == Owner`),
    // so the UI gate is stricter than `canManage`.
    val isOwner = myRole == "Owner"
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var confirmLeave by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { onLoadMembers() }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = QubeePalette.Panel,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 22.dp, vertical = 18.dp),
        ) {
            QubeeStatusPill("GROUP DETAILS")
            Spacer(Modifier.height(10.dp))
            Text(
                groupName.ifBlank { "Group" },
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Black,
            )
            Spacer(Modifier.height(4.dp))
            QubeeMutedText("Member roster, fetched live from the Rust core.")

            if (canManage) {
                Spacer(Modifier.height(14.dp))
                OutlinedButton(
                    onClick = onAddMember,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Add member", color = QubeePalette.Cyan)
                }
            }

            Spacer(Modifier.height(16.dp))

            when {
                members == null -> LoadingMembers()
                members.isEmpty() -> EmptyMembers()
                else -> MemberList(
                    members = members,
                    myIdentityIdHex = myIdentityIdHex,
                    canManage = canManage,
                    canPromote = isOwner,
                    onRemoveMember = onRemoveMember,
                    onPromoteMember = onPromoteMember,
                    onTransferOwnership = onTransferOwnership,
                )
            }

            Spacer(Modifier.height(20.dp))
            OutlinedButton(
                onClick = { confirmLeave = true },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Leave group", color = QubeePalette.Cyan)
            }
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text("Leave $groupName?") },
            text = {
                Text(
                    "You'll stop receiving messages and the remaining members will rotate the group key. The conversation stays in your inbox so you can scroll back through history, but you can't post or decrypt new messages.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    onLeaveGroup()
                    onDismiss()
                }) { Text("Leave", color = QubeePalette.Cyan) }
            },
            dismissButton = {
                TextButton(onClick = { confirmLeave = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun LoadingMembers() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(24.dp),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(color = QubeePalette.Cyan)
    }
}

@Composable
private fun EmptyMembers() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "No members yet",
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(6.dp))
        QubeeMutedText(
            text = "The Rust core doesn't have a roster for this group yet — your invite acceptance may still be in flight.",
        )
    }
}

@Composable
private fun MemberList(
    members: List<GroupMemberInfo>,
    myIdentityIdHex: String?,
    canManage: Boolean,
    canPromote: Boolean,
    onRemoveMember: (String) -> Unit,
    onPromoteMember: (memberIdHex: String, newRole: String) -> Unit,
    onTransferOwnership: (memberIdHex: String) -> Unit,
) {
    var pendingRemove by remember { mutableStateOf<GroupMemberInfo?>(null) }
    var pendingPromote by remember { mutableStateOf<GroupMemberInfo?>(null) }
    var pendingTransfer by remember { mutableStateOf<GroupMemberInfo?>(null) }
    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(members, key = { it.identityIdHex }) { member ->
            val isSelf = myIdentityIdHex != null && member.identityIdHex == myIdentityIdHex
            val isMemberOwner = member.role == "Owner"
            MemberRow(
                member = member,
                isSelf = isSelf,
                canRemove = canManage && !isSelf && member.isActive,
                canPromote = canPromote && !isSelf && member.isActive && !isMemberOwner,
                onRequestRemove = { pendingRemove = member },
                onRequestPromote = { pendingPromote = member },
            )
        }
    }
    val removeTarget = pendingRemove
    if (removeTarget != null) {
        AlertDialog(
            onDismissRequest = { pendingRemove = null },
            title = { Text("Remove ${removeTarget.displayName.ifBlank { "this member" }}?") },
            text = {
                Text(
                    "The Rust core will rotate the group key and the removed member loses access to new messages. They keep their copy of past traffic up to the rotation point.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onRemoveMember(removeTarget.identityIdHex)
                    pendingRemove = null
                }) { Text("Remove", color = QubeePalette.Cyan) }
            },
            dismissButton = {
                TextButton(onClick = { pendingRemove = null }) { Text("Cancel") }
            },
        )
    }
    val promoteTarget = pendingPromote
    if (promoteTarget != null) {
        RolePickerDialog(
            member = promoteTarget,
            onDismiss = { pendingPromote = null },
            onPick = { newRole ->
                onPromoteMember(promoteTarget.identityIdHex, newRole)
                pendingPromote = null
            },
            onRequestTransferOwnership = {
                // Hand off from role picker to the transfer
                // confirmation. The transfer is asymmetric (the
                // donor *also* changes role, irreversibly) so it
                // gets its own confirm sheet rather than living
                // in the role picker proper.
                pendingPromote = null
                pendingTransfer = promoteTarget
            },
        )
    }
    val transferTarget = pendingTransfer
    if (transferTarget != null) {
        AlertDialog(
            onDismissRequest = { pendingTransfer = null },
            title = {
                Text(
                    text = "Transfer ownership to ${transferTarget.displayName.ifBlank { "this member" }}?",
                )
            },
            text = {
                Text(
                    "You'll lose Owner privileges and become Admin. " +
                        "${transferTarget.displayName.ifBlank { "They" }} will become Owner. " +
                        "The Rust core broadcasts a signed atomic role swap; remaining members " +
                        "converge on the new view. The group key is not rotated, so you keep " +
                        "full read access as Admin.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onTransferOwnership(transferTarget.identityIdHex)
                    pendingTransfer = null
                }) { Text("Transfer", color = QubeePalette.Cyan) }
            },
            dismissButton = {
                TextButton(onClick = { pendingTransfer = null }) { Text("Cancel") }
            },
        )
    }
}

/**
 * Owner-only role picker. Lists the four assignable roles (`Owner`
 * is excluded — transferring ownership has its own flow that this
 * batch doesn't ship). Greys out the row matching the member's
 * current role.
 *
 * Strings here must match the small fixed vocabulary the JNI
 * accepts (`Admin` / `Moderator` / `Member` / `Observer`); see
 * `Java_com_qubee_messenger_crypto_QubeeManager_nativePromoteMember`
 * in `src/jni_api.rs` for the canonical list.
 */
@Composable
private fun RolePickerDialog(
    member: GroupMemberInfo,
    onDismiss: () -> Unit,
    onPick: (newRole: String) -> Unit,
    onRequestTransferOwnership: () -> Unit,
) {
    val roles = listOf("Admin", "Moderator", "Member", "Observer")
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Change role for ${member.displayName.ifBlank { "this member" }}") },
        text = {
            Column {
                QubeeMutedText(
                    text = "Currently: ${member.role}. The Rust core broadcasts a signed RoleChange so other members converge on the new view.",
                )
                Spacer(Modifier.height(12.dp))
                roles.forEach { role ->
                    val isCurrent = role == member.role
                    TextButton(
                        onClick = { if (!isCurrent) onPick(role) },
                        enabled = !isCurrent,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = if (isCurrent) "$role (current)" else role,
                            color = if (isCurrent) QubeeMutedColor else QubeePalette.Cyan,
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                TextButton(
                    onClick = onRequestTransferOwnership,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = "Transfer ownership →",
                        color = QubeePalette.Cyan,
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

private val QubeeMutedColor: androidx.compose.ui.graphics.Color
    get() = QubeePalette.Text.copy(alpha = 0.45f)

@Composable
private fun MemberRow(
    member: GroupMemberInfo,
    isSelf: Boolean,
    canRemove: Boolean,
    canPromote: Boolean,
    onRequestRemove: () -> Unit,
    onRequestPromote: () -> Unit,
) {
    val initials = member.displayName
        .split(' ', '\t', '\n')
        .mapNotNull { it.firstOrNull()?.toString()?.uppercase() }
        .take(2)
        .joinToString(separator = "")
        .ifBlank { member.displayName.take(2).uppercase() }
        .ifBlank { member.identityIdHex.take(2).uppercase() }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(QubeePalette.PanelAlt)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(38.dp)
                .clip(CircleShape)
                .background(QubeePalette.Cyan.copy(alpha = 0.2f)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                initials,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = member.displayName.ifBlank { "Unnamed member" },
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            QubeeMutedText(
                text = if (member.isActive) member.role else "${member.role} · removed",
            )
        }
        if (isSelf) {
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = QubeePalette.Cyan.copy(alpha = 0.18f),
                modifier = Modifier.padding(start = 8.dp),
            ) {
                Text(
                    "You",
                    color = QubeePalette.Cyan,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
        } else {
            // Right-edge actions for non-self rows. Owner / admin
            // can remove; owner alone can change role. Both can be
            // visible on the same row when the viewer is the owner.
            if (canPromote) {
                TextButton(onClick = onRequestPromote) {
                    Text("Role", color = QubeePalette.Cyan)
                }
            }
            if (canRemove) {
                TextButton(onClick = onRequestRemove) {
                    Text("Remove", color = QubeePalette.Cyan)
                }
            }
        }
    }
}
