package com.qubee.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.model.ConversationSummary
import com.qubee.messenger.model.UserProfile
import com.qubee.messenger.ui.theme.*

@Composable
fun ConversationsScreen(
    profile: UserProfile? = null,
    nativeStatus: String = "ready",
    relayStatus: String = "connected",
    conversations: List<ConversationSummary> = emptyList(),
    onConversationClick: (String) -> Unit = {},
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark),
        contentPadding = PaddingValues(vertical = 4.dp),
    ) {
        items(conversations, key = { it.id }) { convo ->
            ConversationRow(
                conversation = convo,
                onClick = { onConversationClick(convo.id) },
            )
        }

        if (conversations.isEmpty()) {
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(48.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = "No conversations yet",
                        style = MaterialTheme.typography.titleMedium,
                        color = QubeeMuted,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Tap + to invite a contact",
                        style = MaterialTheme.typography.bodySmall,
                        color = QubeeSubtle,
                    )
                }
            }
        }
    }
}

@Composable
private fun ConversationRow(
    conversation: ConversationSummary,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // Avatar
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(QubeePrimaryContainer)
                .border(1.dp, QubeeOutline, RoundedCornerShape(14.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = conversation.title.take(1).uppercase(),
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                color = QubeeSecondary,
            )
        }

        // Name, badges, preview
        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = conversation.title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = QubeeOnDark,
                )
                if (conversation.verified) {
                    Text("✓", color = QubeePrimary, fontSize = 12.sp)
                }
                if (conversation.postQuantum) {
                    Text(
                        text = "PQ",
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace,
                        color = QubeePrimaryDim,
                        modifier = Modifier
                            .background(QubeePrimaryContainer, RoundedCornerShape(4.dp))
                            .padding(horizontal = 5.dp, vertical = 1.dp),
                    )
                }
            }
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = conversation.lastMessage,
                style = MaterialTheme.typography.bodySmall,
                color = QubeeMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        // Time and unread badge
        Column(
            horizontalAlignment = Alignment.End,
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = conversation.timeLabel,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = QubeeSubtle,
            )
            if (conversation.unreadCount > 0) {
                Box(
                    modifier = Modifier
                        .defaultMinSize(minWidth = 20.dp)
                        .height(20.dp)
                        .background(QubeePrimary, CircleShape)
                        .padding(horizontal = 6.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "${conversation.unreadCount}",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = QubeeBackgroundDark,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }
}
