package com.qubee.messenger.ui.main

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeIconButton
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeTrust
import com.qubee.messenger.ui.theme.QubeeTrustShield
import com.qubee.messenger.ui.theme.qubeeInitials
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class ConversationsFragment : Fragment() {

    private val viewModel: ConversationsViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            val state by viewModel.uiState.collectAsStateWithLifecycle()
            ConversationsScreen(
                state = state,
                onConversationClick = { summary ->
                    val args = Bundle().apply { putString("contactId", summary.peerId) }
                    findNavController().navigate(R.id.action_to_chat, args)
                },
                onStartContact = {
                    findNavController().navigate(R.id.action_to_contact_selection)
                },
                onOpenInvites = {
                    findNavController().navigate(R.id.action_to_group_invite)
                },
                onAddSomeone = {
                    findNavController().navigate(R.id.action_to_connect)
                },
            )
        }
    }
}

@Composable
private fun ConversationsScreen(
    state: ConversationsUiState,
    onConversationClick: (ConversationSummaryUi) -> Unit,
    onStartContact: () -> Unit,
    onOpenInvites: () -> Unit,
    onAddSomeone: () -> Unit,
) {
    QubeeTheme {
        QubeeScreen {
            Column(modifier = Modifier.fillMaxSize()) {
                ConversationsHeader(onOpenInvites = onOpenInvites)
                PrivacyBanner()
                when {
                    state.isLoading -> LoadingConversations()
                    state.conversations.isEmpty() -> EmptyConversations(
                        onAddSomeone = onAddSomeone,
                        onStartContact = onStartContact,
                    )
                    else -> ConversationList(
                        conversations = state.conversations,
                        onConversationClick = onConversationClick,
                    )
                }
            }
            if (state.conversations.isNotEmpty()) {
                FloatingActionButton(
                    onClick = onStartContact,
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(20.dp),
                    shape = CircleShape,
                    containerColor = QubeePalette.Cyan,
                    contentColor = QubeePalette.Void,
                ) {
                    Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.chats_new_chat))
                }
            }
        }
    }
}

@Composable
private fun ConversationsHeader(onOpenInvites: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, end = 16.dp, top = 20.dp, bottom = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(QubeePalette.Cyan, CircleShape),
            )
            Spacer(Modifier.width(10.dp))
            Text(
                stringResource(R.string.title_conversations),
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineMedium,
            )
        }
        QubeeIconButton(
            icon = Icons.Filled.GroupAdd,
            contentDescription = stringResource(R.string.chats_new_group),
            onClick = onOpenInvites,
        )
    }
}

@Composable
private fun PrivacyBanner() {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 4.dp),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
        color = QubeePalette.Panel,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Filled.GppGood,
                contentDescription = null,
                tint = QubeePalette.Cyan,
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(12.dp))
            QubeeMutedText(
                stringResource(R.string.chats_privacy_banner),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun LoadingConversations() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(color = QubeePalette.Cyan)
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun ConversationList(
    conversations: List<ConversationSummaryUi>,
    onConversationClick: (ConversationSummaryUi) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 6.dp, bottom = 96.dp),
    ) {
        items(conversations, key = { it.conversationId }) { summary ->
            ConversationRow(
                summary = summary,
                onClick = { onConversationClick(summary) },
            )
        }
    }
}

@Composable
private fun ConversationRow(
    summary: ConversationSummaryUi,
    onClick: () -> Unit,
) {
    val unread = summary.unreadCount > 0
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp)
            .heightIn(min = 52.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (summary.isGroup) {
            QubeeAvatar(initials = "", icon = Icons.Outlined.Group, color = QubeePalette.MutedText)
        } else {
            QubeeAvatar(initials = summary.title.qubeeInitials())
        }
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = summary.title,
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.titleMedium.copy(fontSize = 16.sp),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (summary.isPinned) {
                    Icon(
                        imageVector = Icons.Filled.PushPin,
                        contentDescription = "Pinned",
                        tint = QubeePalette.MutedText,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                }
                Text(
                    text = summary.timestamp,
                    color = if (unread) QubeePalette.Cyan else QubeePalette.MutedText,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = if (unread) FontWeight.Bold else FontWeight.Normal,
                )
            }
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                val trust = summary.trust
                if (trust != null) {
                    QubeeTrustShield(trust)
                    Spacer(Modifier.width(6.dp))
                }
                val keyChanged = trust == QubeeTrust.KeyChanged || trust == QubeeTrust.Compromised
                val previewText = when {
                    keyChanged -> stringResource(R.string.chats_key_changed_hint)
                    summary.preview.isNotBlank() -> summary.preview
                    summary.isGroup -> stringResource(R.string.chats_private_group)
                    else -> stringResource(R.string.chats_private_chat)
                }
                Text(
                    text = previewText,
                    color = when {
                        keyChanged -> trust!!.color
                        unread -> QubeePalette.Text
                        else -> QubeePalette.MutedText
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (unread || keyChanged) FontWeight.SemiBold else FontWeight.Normal,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (summary.isMuted) {
                    Spacer(Modifier.width(6.dp))
                    Icon(
                        imageVector = Icons.Filled.NotificationsOff,
                        contentDescription = "Muted",
                        tint = QubeePalette.MutedText,
                        modifier = Modifier.size(14.dp),
                    )
                }
                if (unread) {
                    Spacer(Modifier.width(8.dp))
                    UnreadBadge(summary.unreadCount)
                }
            }
        }
    }
}

@Composable
private fun UnreadBadge(count: Int) {
    Surface(
        shape = androidx.compose.foundation.shape.RoundedCornerShape(11.dp),
        color = QubeePalette.Cyan,
    ) {
        Text(
            text = count.coerceAtMost(99).toString(),
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
            color = QubeePalette.Void,
            style = MaterialTheme.typography.labelMedium,
        )
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun EmptyConversations(
    onAddSomeone: () -> Unit,
    onStartContact: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 28.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.chats_empty_title),
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.chats_empty_body),
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        QubeePrimaryButton(
            text = stringResource(R.string.chats_add_someone),
            onClick = onAddSomeone,
            icon = Icons.Filled.Add,
        )
        Spacer(Modifier.height(10.dp))
        QubeeSecondaryButton(
            text = stringResource(R.string.chats_pick_contact),
            onClick = onStartContact,
        )
    }
}
