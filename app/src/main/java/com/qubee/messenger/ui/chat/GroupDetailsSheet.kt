package com.qubee.messenger.ui.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qubee.messenger.R
import com.qubee.messenger.groups.GroupMemberInfo
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeDangerButton
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.qubeeInitials

/**
 * Bottom sheet for a group chat: the roster from the Rust core, with
 * add, remove, role and ownership actions gated by the viewer's own
 * role (`Owner` / `Admin` may remove; only `Owner` may change roles or
 * hand over ownership, mirroring `GroupManager`'s checks).
 *
 * The roster loads lazily on sheet open. While the load is in flight
 * `members == null` and a spinner renders; an empty list (group not
 * yet known Rust-side) gets the explicit empty copy instead.
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
    val canManage = myRole == "Owner" || myRole == "Admin"
    val isOwner = myRole == "Owner"
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var confirmLeave by remember { mutableStateOf(false) }
    val name = groupName.ifBlank { "Group" }

    LaunchedEffect(Unit) { onLoadMembers() }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = QubeePalette.Panel,
        tonalElevation = 0.dp,
        dragHandle = null,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 18.dp, vertical = 14.dp),
        ) {
            Surface(
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .width(46.dp)
                    .height(4.dp),
                shape = RoundedCornerShape(999.dp),
                color = QubeePalette.PanelAlt,
            ) {}
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                QubeeAvatar(initials = "", icon = Icons.Outlined.Group, color = QubeePalette.MutedText)
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = name,
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.headlineSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (members != null) {
                        QubeeMutedText(
                            text = stringResource(R.string.group_sheet_members, members.count { it.isActive }),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }

            if (canManage) {
                Spacer(Modifier.height(16.dp))
                QubeeSecondaryButton(
                    text = stringResource(R.string.group_sheet_add),
                    onClick = onAddMember,
                    icon = Icons.Filled.PersonAdd,
                )
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
            QubeeDangerButton(
                text = stringResource(R.string.group_sheet_leave),
                onClick = { confirmLeave = true },
            )
            Spacer(Modifier.height(12.dp))
        }
    }

    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text(stringResource(R.string.group_sheet_leave_title, name)) },
            text = { Text(stringResource(R.string.group_sheet_leave_body), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = {
                TextButton(onClick = {
                    confirmLeave = false
                    onLeaveGroup()
                    onDismiss()
                }) { Text(stringResource(R.string.group_sheet_leave_ok), color = QubeePalette.Danger) }
            },
            dismissButton = {
                TextButton(onClick = { confirmLeave = false }) { Text(stringResource(R.string.cancel), color = QubeePalette.MutedText) }
            },
        )
    }
}

@Composable
private fun LoadingMembers() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CircularProgressIndicator(color = QubeePalette.Cyan, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(12.dp))
        QubeeMutedText(stringResource(R.string.group_sheet_loading))
    }
}

@Composable
private fun EmptyMembers() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
    ) {
        Text(
            text = stringResource(R.string.group_sheet_empty_title),
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(4.dp))
        QubeeMutedText(stringResource(R.string.group_sheet_empty_body), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun MemberList(
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
    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
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
            title = { Text(stringResource(R.string.group_sheet_remove_title, removeTarget.label())) },
            text = { Text(stringResource(R.string.group_sheet_remove_body), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = {
                TextButton(onClick = {
                    onRemoveMember(removeTarget.identityIdHex)
                    pendingRemove = null
                }) { Text(stringResource(R.string.group_sheet_remove), color = QubeePalette.Danger) }
            },
            dismissButton = {
                TextButton(onClick = { pendingRemove = null }) { Text(stringResource(R.string.cancel), color = QubeePalette.MutedText) }
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
                // Ownership transfer also changes the donor's role, so it
                // gets its own confirmation rather than a row in the picker.
                pendingPromote = null
                pendingTransfer = promoteTarget
            },
        )
    }
    val transferTarget = pendingTransfer
    if (transferTarget != null) {
        AlertDialog(
            onDismissRequest = { pendingTransfer = null },
            title = { Text(stringResource(R.string.group_sheet_transfer_title, transferTarget.label())) },
            text = { Text(stringResource(R.string.group_sheet_transfer_body), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = {
                TextButton(onClick = {
                    onTransferOwnership(transferTarget.identityIdHex)
                    pendingTransfer = null
                }) { Text(stringResource(R.string.group_sheet_transfer_ok), color = QubeePalette.Cyan) }
            },
            dismissButton = {
                TextButton(onClick = { pendingTransfer = null }) { Text(stringResource(R.string.cancel), color = QubeePalette.MutedText) }
            },
        )
    }
}

/**
 * Owner-only role picker. The four assignable roles are the fixed
 * vocabulary `nativePromoteMember` accepts (`Admin` / `Moderator` /
 * `Member` / `Observer`); ownership moves through its own confirmation.
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
        title = { Text(stringResource(R.string.group_sheet_role_title, member.label())) },
        text = {
            Column {
                QubeeMutedText(stringResource(R.string.group_sheet_role_now, member.role))
                Spacer(Modifier.height(8.dp))
                roles.forEach { role ->
                    val isCurrent = role == member.role
                    TextButton(
                        onClick = { if (!isCurrent) onPick(role) },
                        enabled = !isCurrent,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = if (isCurrent) stringResource(R.string.group_sheet_role_current, role) else role,
                            color = if (isCurrent) QubeePalette.MutedText else QubeePalette.Cyan,
                        )
                    }
                }
                Spacer(Modifier.height(4.dp))
                TextButton(onClick = onRequestTransferOwnership, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.group_sheet_transfer), color = QubeePalette.Warning)
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel), color = QubeePalette.MutedText) }
        },
    )
}

@Composable
private fun GroupMemberInfo.label(): String = displayName.ifBlank { stringResource(R.string.group_sheet_unnamed) }

@Composable
private fun MemberRow(
    member: GroupMemberInfo,
    isSelf: Boolean,
    canRemove: Boolean,
    canPromote: Boolean,
    onRequestRemove: () -> Unit,
    onRequestPromote: () -> Unit,
) {
    val name = member.label()
    val initials = member.displayName.ifBlank { member.identityIdHex.take(2) }.qubeeInitials()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QubeeAvatar(initials = initials, size = 40.dp)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = name,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            QubeeMutedText(
                text = if (member.isActive) member.role else stringResource(R.string.group_sheet_removed, member.role),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (isSelf) {
            QubeeStatusPill(stringResource(R.string.group_sheet_you))
        } else {
            if (canPromote) {
                TextButton(onClick = onRequestPromote) {
                    Text(stringResource(R.string.group_sheet_role), color = QubeePalette.Cyan)
                }
            }
            if (canRemove) {
                TextButton(onClick = onRequestRemove) {
                    Text(stringResource(R.string.group_sheet_remove), color = QubeePalette.Cyan)
                }
            }
        }
    }
    Divider(modifier = Modifier.padding(start = 52.dp), color = QubeePalette.PanelAlt)
}
