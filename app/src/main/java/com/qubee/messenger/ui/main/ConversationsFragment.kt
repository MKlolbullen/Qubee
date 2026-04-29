package com.qubee.messenger.ui.main

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.NotificationsOff
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeHeroMark
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePanelBorder
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQuantumBrush
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
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
            val state by viewModel.uiState.collectAsState()
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
) {
    QubeeTheme {
        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 22.dp, vertical = 26.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                ConversationsHeader()
                Spacer(Modifier.height(22.dp))

                when {
                    state.isLoading -> LoadingConversations()
                    state.conversations.isEmpty() -> EmptyConversations(
                        onStartContact = onStartContact,
                        onOpenInvites = onOpenInvites,
                    )
                    else -> ConversationList(
                        conversations = state.conversations,
                        onConversationClick = onConversationClick,
                        onStartContact = onStartContact,
                    )
                }
            }
        }
    }
}

@Composable
private fun ConversationsHeader() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            QubeeStatusPill("P2P MESSENGER")
            Spacer(Modifier.height(12.dp))
            Text(
                "Chats",
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Black,
            )
            QubeeMutedText("Encrypted conversations, local-first state.")
        }
        QubeeHeroMark(modifier = Modifier.size(72.dp))
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
private fun ConversationList(
    conversations: List<ConversationSummaryUi>,
    onConversationClick: (ConversationSummaryUi) -> Unit,
    onStartContact: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            QubeePrimaryButton(
                text = "New secure chat",
                onClick = onStartContact,
                modifier = Modifier.weight(1f),
            )
        }
        Spacer(Modifier.height(14.dp))
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(conversations, key = { it.conversationId }) { summary ->
                ConversationRow(
                    summary = summary,
                    onClick = { onConversationClick(summary) },
                )
            }
        }
    }
}

@Composable
private fun ConversationRow(
    summary: ConversationSummaryUi,
    onClick: () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(26.dp),
        color = QubeePalette.Panel.copy(alpha = 0.92f),
        border = BorderStroke(1.dp, QubeePanelBorder),
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ConversationAvatar(summary)
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = summary.title,
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = summary.timestamp,
                        color = QubeePalette.MutedText,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Spacer(Modifier.height(5.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SecurityMiniPill(summary.securityState)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = summary.preview,
                        color = QubeePalette.MutedText,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                }
                if (summary.isPinned || summary.isMuted || summary.unreadCount > 0) {
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (summary.isPinned) TinyMetaIcon(Icons.Default.PushPin, QubeePalette.Cyan)
                        if (summary.isMuted) TinyMetaIcon(Icons.Default.NotificationsOff, QubeePalette.MutedText)
                        if (summary.unreadCount > 0) UnreadBadge(summary.unreadCount)
                    }
                }
            }
        }
    }
}

@Composable
private fun ConversationAvatar(summary: ConversationSummaryUi) {
    Surface(
        modifier = Modifier.size(54.dp),
        shape = CircleShape,
        color = QubeePalette.Cyan.copy(alpha = 0.10f),
        border = BorderStroke(1.dp, QubeeQuantumBrush),
    ) {
        Box(contentAlignment = Alignment.Center) {
            if (summary.isGroup) {
                Icon(
                    imageVector = Icons.Default.Group,
                    contentDescription = null,
                    tint = QubeePalette.Cyan,
                    modifier = Modifier.size(25.dp),
                )
            } else {
                Text(
                    text = summary.title.initials(),
                    color = QubeePalette.Cyan,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Black,
                )
            }
        }
    }
}

@Composable
private fun SecurityMiniPill(state: ConversationListSecurityState) {
    val color = when (state) {
        ConversationListSecurityState.PqReady -> QubeePalette.Green
        ConversationListSecurityState.Unverified -> QubeePalette.Warning
        ConversationListSecurityState.Offline -> QubeePalette.Blue
    }
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = color.copy(alpha = 0.10f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.45f)),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = if (state == ConversationListSecurityState.PqReady) Icons.Default.VerifiedUser else Icons.Default.Shield,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(12.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text(
                text = state.label,
                color = color,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Black,
            )
        }
    }
}

@Composable
private fun TinyMetaIcon(icon: ImageVector, color: Color) {
    Icon(
        imageVector = icon,
        contentDescription = null,
        tint = color,
        modifier = Modifier.size(15.dp),
    )
}

@Composable
private fun UnreadBadge(count: Int) {
    Surface(
        shape = CircleShape,
        color = QubeePalette.Cyan,
    ) {
        Text(
            text = count.coerceAtMost(99).toString(),
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
            color = QubeePalette.Void,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Black,
        )
    }
}

@Composable
private fun EmptyConversations(
    onStartContact: () -> Unit,
    onOpenInvites: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        QubeePanel {
            EmptySignalGlyph()
            Spacer(Modifier.height(18.dp))
            Text(
                "No secure channels yet",
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineSmall,
            )
            Spacer(Modifier.height(8.dp))
            QubeeMutedText(
                "Add a verified contact or generate a group invite to open your first post-quantum conversation. Until then, the hive is quiet.",
            )
            Spacer(Modifier.height(20.dp))
            QubeePrimaryButton(
                text = "Choose contact",
                onClick = onStartContact,
            )
            Spacer(Modifier.height(12.dp))
            QubeeSecondaryButton(
                text = "Create / scan group invite",
                onClick = onOpenInvites,
            )
        }

        Spacer(Modifier.height(18.dp))

        QubeePanel {
            Text(
                "Security baseline",
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleLarge,
            )
            Spacer(Modifier.height(14.dp))
            SecurityLine(
                icon = Icons.Default.Security,
                title = "Local identity",
                body = "Your private identity material stays on this device.",
            )
            Spacer(Modifier.height(12.dp))
            SecurityLine(
                icon = Icons.Default.QrCodeScanner,
                title = "QR trust ceremony",
                body = "First contact should be scanned or compared, not guessed from a directory.",
            )
            Spacer(Modifier.height(12.dp))
            SecurityLine(
                icon = Icons.Default.GroupAdd,
                title = "Small groups first",
                body = "Invite flow is intentionally explicit so group membership does not become metadata soup.",
            )
        }
    }
}

@Composable
private fun EmptySignalGlyph() {
    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = Alignment.Center,
    ) {
        Surface(
            modifier = Modifier.size(112.dp),
            shape = CircleShape,
            color = QubeePalette.Cyan.copy(alpha = 0.10f),
            border = BorderStroke(1.dp, QubeeQuantumBrush),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = QubeePalette.Cyan,
                    modifier = Modifier.size(42.dp),
                )
            }
        }
    }
}

@Composable
private fun SecurityLine(
    icon: ImageVector,
    title: String,
    body: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
    ) {
        Surface(
            modifier = Modifier.size(36.dp),
            shape = CircleShape,
            color = QubeePalette.Cyan.copy(alpha = 0.10f),
            border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.35f)),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = QubeePalette.Cyan,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
        Spacer(Modifier.size(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                title,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
            )
            QubeeMutedText(body)
        }
    }
}

private fun String.initials(): String = split(" ")
    .filter { it.isNotBlank() }
    .take(2)
    .joinToString("") { it.first().uppercaseChar().toString() }
    .ifBlank { "Q" }
