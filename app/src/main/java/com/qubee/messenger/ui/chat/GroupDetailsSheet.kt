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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
    onLoadMembers: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

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
            Spacer(Modifier.height(16.dp))

            when {
                members == null -> LoadingMembers()
                members.isEmpty() -> EmptyMembers()
                else -> MemberList(members)
            }
        }
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
private fun MemberList(members: List<GroupMemberInfo>) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(members, key = { it.identityIdHex }) { member ->
            MemberRow(member)
        }
    }
}

@Composable
private fun MemberRow(member: GroupMemberInfo) {
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
    }
}
