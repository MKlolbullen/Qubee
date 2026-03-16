package com.qubee.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.model.ConversationSummary
import com.qubee.messenger.model.MessageItem
import com.qubee.messenger.ui.components.StatusChip
import com.qubee.messenger.ui.theme.*

@Composable
fun ChatScreen(
    conversation: ConversationSummary? = null,
    messages: List<MessageItem> = emptyList(),
    relayStatus: String = "connected",
    safetyCode: String? = null,
    onVerifyContact: () -> Unit = {},
    onOpenTrustDetails: () -> Unit = {},
    onSend: (String) -> Unit = {},
) {
    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark),
    ) {
        // Encryption status bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(QubeeSurfaceDark)
                .border(width = 1.dp, color = QubeeOutline)
                .padding(horizontal = 16.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            StatusChip(label = "E2E", ok = true)
            StatusChip(label = "PQ", ok = conversation?.postQuantum == true)
            StatusChip(label = "Verified", ok = conversation?.verified == true)
        }

        // Messages
        LazyColumn(
            modifier = Modifier.weight(1f),
            state = listState,
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(messages, key = { it.id }) { message ->
                MessageBubble(message = message)
            }
        }

        // Input bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(QubeeSurfaceDark)
                .border(width = 1.dp, color = QubeeOutline)
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            BasicTextField(
                value = draft,
                onValueChange = { draft = it },
                textStyle = MaterialTheme.typography.bodyMedium.copy(color = QubeeOnDark),
                cursorBrush = SolidColor(QubeePrimary),
                singleLine = false,
                maxLines = 4,
                modifier = Modifier.weight(1f),
                decorationBox = { innerTextField ->
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(24.dp))
                            .background(QubeeSurfaceVariantDark)
                            .border(1.dp, QubeeOutline, RoundedCornerShape(24.dp))
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                    ) {
                        if (draft.isEmpty()) {
                            Text("Message…", style = MaterialTheme.typography.bodyMedium, color = QubeeSubtle)
                        }
                        innerTextField()
                    }
                },
            )

            IconButton(
                onClick = {
                    if (draft.isNotBlank()) {
                        onSend(draft.trim())
                        draft = ""
                    }
                },
                modifier = Modifier
                    .size(44.dp)
                    .background(QubeePrimary, CircleShape),
            ) {
                Icon(
                    imageVector = Icons.Rounded.ArrowUpward,
                    contentDescription = "Send",
                    tint = QubeeBackgroundDark,
                )
            }
        }
    }
}

@Composable
private fun MessageBubble(message: MessageItem) {
    val isMine = message.isMine
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (isMine) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 300.dp)
                .clip(
                    RoundedCornerShape(
                        topStart = 16.dp,
                        topEnd = 16.dp,
                        bottomStart = if (isMine) 16.dp else 4.dp,
                        bottomEnd = if (isMine) 4.dp else 16.dp,
                    ),
                )
                .background(if (isMine) QubeePrimaryContainer else QubeeSurfaceVariantDark)
                .border(
                    1.dp,
                    if (isMine) QubeePrimary.copy(alpha = 0.2f) else QubeeOutline,
                    RoundedCornerShape(
                        topStart = 16.dp,
                        topEnd = 16.dp,
                        bottomStart = if (isMine) 16.dp else 4.dp,
                        bottomEnd = if (isMine) 4.dp else 16.dp,
                    ),
                )
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Text(
                text = message.text,
                style = MaterialTheme.typography.bodyMedium,
                color = QubeeOnDark,
                lineHeight = 21.sp,
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = message.timeLabel,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = QubeeSubtle,
                modifier = Modifier.align(Alignment.End),
            )
        }
    }
}
