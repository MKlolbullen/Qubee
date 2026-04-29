package com.qubee.messenger.ui.chat

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanelBorder
import com.qubee.messenger.ui.theme.QubeeQuantumBrush
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    onBackClick: () -> Unit,
) {
    QubeeTheme {
        val uiState by viewModel.uiState.collectAsState()
        var inputText by remember { mutableStateOf("") }

        Scaffold(
            containerColor = QubeePalette.Void,
            topBar = {
                SecureChatTopBar(
                    contactName = uiState.contactName,
                    securityState = uiState.securityState,
                    onBackClick = onBackClick,
                )
            },
            bottomBar = {
                ChatInputBar(
                    text = inputText,
                    onTextChanged = { inputText = it },
                    onSend = {
                        viewModel.sendMessage(inputText)
                        inputText = ""
                    },
                    onAttach = viewModel::onAttachFile,
                    onCamera = viewModel::onTakePhoto,
                    onMic = viewModel::onRecordAudio,
                )
            },
        ) { padding ->
            QubeeScreen(modifier = Modifier.padding(padding)) {
                Column(modifier = Modifier.fillMaxSize()) {
                    SecurityBanner(uiState.securityState)
                    if (uiState.messages.isEmpty()) {
                        EmptyChatState(contactName = uiState.contactName)
                    } else {
                        LazyColumn(
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 12.dp),
                            reverseLayout = true,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(uiState.messages.reversed(), key = { it.id }) { msg ->
                                MessageBubble(msg)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SecureChatTopBar(
    contactName: String,
    securityState: ConversationSecurityState,
    onBackClick: () -> Unit,
) {
    Surface(
        color = QubeePalette.Panel.copy(alpha = 0.96f),
        border = BorderStroke(1.dp, QubeePanelBorder),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 6.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBackClick) {
                Icon(
                    Icons.Default.ArrowBack,
                    contentDescription = "Back",
                    tint = QubeePalette.Text,
                )
            }
            PeerAvatar(contactName)
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = contactName,
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = securityState.icon,
                        contentDescription = null,
                        tint = securityState.color,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(Modifier.width(5.dp))
                    Text(
                        text = securityState.label,
                        color = securityState.color,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            IconButton(onClick = { /* TODO: conversation details */ }) {
                Icon(
                    Icons.Default.MoreVert,
                    contentDescription = "Conversation options",
                    tint = QubeePalette.MutedText,
                )
            }
        }
    }
}

@Composable
private fun PeerAvatar(name: String) {
    val initials = name
        .split(" ")
        .filter { it.isNotBlank() }
        .take(2)
        .joinToString("") { it.first().uppercaseChar().toString() }
        .ifBlank { "Q" }

    Surface(
        modifier = Modifier.size(46.dp),
        shape = CircleShape,
        color = QubeePalette.Cyan.copy(alpha = 0.10f),
        border = BorderStroke(1.dp, QubeeQuantumBrush),
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = initials,
                color = QubeePalette.Cyan,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Black,
            )
        }
    }
}

@Composable
private fun SecurityBanner(securityState: ConversationSecurityState) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 12.dp),
        shape = RoundedCornerShape(24.dp),
        color = securityState.color.copy(alpha = 0.10f),
        border = BorderStroke(1.dp, securityState.color.copy(alpha = 0.42f)),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = securityState.icon,
                contentDescription = null,
                tint = securityState.color,
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = securityState.label,
                    color = securityState.color,
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = securityState.description,
                    color = QubeePalette.MutedText,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun EmptyChatState(contactName: String) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                modifier = Modifier.size(88.dp),
                shape = CircleShape,
                color = QubeePalette.Cyan.copy(alpha = 0.10f),
                border = BorderStroke(1.dp, QubeeQuantumBrush),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = null,
                        tint = QubeePalette.Cyan,
                        modifier = Modifier.size(34.dp),
                    )
                }
            }
            Spacer(Modifier.height(18.dp))
            Text(
                text = "Secure channel ready",
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineSmall,
            )
            Spacer(Modifier.height(8.dp))
            QubeeMutedText(
                text = "Send the first encrypted message to $contactName. Keep it elegant. Or chaotic. The ratchet does not judge.",
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
fun MessageBubble(msg: UiMessage) {
    val align = if (msg.isFromMe) Alignment.End else Alignment.Start
    val bubbleBrush = if (msg.isFromMe) {
        Brush.linearGradient(
            colors = listOf(
                QubeePalette.Cyan.copy(alpha = 0.28f),
                QubeePalette.Blue.copy(alpha = 0.18f),
            ),
        )
    } else {
        Brush.linearGradient(
            colors = listOf(
                QubeePalette.PanelAlt.copy(alpha = 0.96f),
                QubeePalette.Panel.copy(alpha = 0.92f),
            ),
        )
    }
    val shape = if (msg.isFromMe) {
        RoundedCornerShape(24.dp, 24.dp, 6.dp, 24.dp)
    } else {
        RoundedCornerShape(24.dp, 24.dp, 24.dp, 6.dp)
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = align,
    ) {
        Surface(
            color = Color.Transparent,
            shape = shape,
            border = BorderStroke(
                width = 1.dp,
                brush = if (msg.isFromMe) QubeePanelBorder else Brush.linearGradient(
                    listOf(
                        QubeePalette.Cyan.copy(alpha = 0.22f),
                        QubeePalette.Blue.copy(alpha = 0.10f),
                    ),
                ),
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth(if (msg.text.length > 120) 0.92f else 0.78f)
                    .background(bubbleBrush)
                    .padding(horizontal = 14.dp, vertical = 10.dp),
            ) {
                Text(
                    text = msg.text,
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.bodyLarge,
                )
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.align(Alignment.End),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = msg.status.icon,
                        contentDescription = msg.status.label,
                        tint = msg.status.color,
                        modifier = Modifier.size(13.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = formatMessageTime(msg.timestamp),
                        color = QubeePalette.MutedText,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (msg.isFromMe) {
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = msg.status.label,
                            color = msg.status.color,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun ChatInputBar(
    text: String,
    onTextChanged: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
    onCamera: () -> Unit,
    onMic: () -> Unit,
) {
    Surface(
        color = QubeePalette.Panel.copy(alpha = 0.98f),
        border = BorderStroke(1.dp, QubeePanelBorder),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .imePadding(),
        ) {
            Divider(color = QubeePalette.Cyan.copy(alpha = 0.12f))
            Row(
                modifier = Modifier
                    .padding(horizontal = 10.dp, vertical = 10.dp)
                    .fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onAttach) {
                    Icon(Icons.Default.AttachFile, "Attach file", tint = QubeePalette.MutedText)
                }

                TextField(
                    value = text,
                    onValueChange = onTextChanged,
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(22.dp)),
                    shape = RoundedCornerShape(22.dp),
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = QubeePalette.Void2.copy(alpha = 0.82f),
                        unfocusedContainerColor = QubeePalette.Void2.copy(alpha = 0.82f),
                        focusedTextColor = QubeePalette.Text,
                        unfocusedTextColor = QubeePalette.Text,
                        cursorColor = QubeePalette.Cyan,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                    ),
                    placeholder = {
                        Text("Encrypted message…", color = QubeePalette.MutedText)
                    },
                    maxLines = 5,
                )

                Spacer(Modifier.width(6.dp))

                if (text.isBlank()) {
                    IconButton(onClick = onCamera) {
                        Icon(Icons.Default.CameraAlt, "Camera", tint = QubeePalette.MutedText)
                    }
                    IconButton(onClick = onMic) {
                        Icon(Icons.Default.Mic, "Record audio", tint = QubeePalette.MutedText)
                    }
                } else {
                    IconButton(
                        onClick = onSend,
                        modifier = Modifier
                            .size(46.dp)
                            .background(
                                brush = QubeeQuantumBrush,
                                shape = CircleShape,
                            ),
                    ) {
                        Icon(Icons.Default.Send, "Send", tint = QubeePalette.Void)
                    }
                }
            }
        }
    }
}

private fun formatMessageTime(timestamp: Long): String {
    if (timestamp <= 0L) return "now"
    return SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(timestamp))
}

enum class ConversationSecurityState(
    val label: String,
    val description: String,
    val color: Color,
    val icon: ImageVector,
) {
    PqSessionActive(
        label = "PQ session active",
        description = "Hybrid post-quantum session established. Verify the contact fingerprint before trusting identity-sensitive content.",
        color = QubeePalette.Cyan,
        icon = Icons.Default.VerifiedUser,
    ),
    Unverified(
        label = "Unverified contact",
        description = "Messages are encrypted, but this contact has not been manually verified yet.",
        color = QubeePalette.Warning,
        icon = Icons.Default.ErrorOutline,
    ),
    OfflineQueued(
        label = "Offline queue",
        description = "Messages will be encrypted locally and sent when the P2P path returns.",
        color = QubeePalette.Blue,
        icon = Icons.Default.Timer,
    ),
}

enum class MessageDeliveryState(
    val label: String,
    val color: Color,
    val icon: ImageVector,
) {
    Encrypting("encrypting", QubeePalette.Warning, Icons.Default.Lock),
    Queued("queued", QubeePalette.Blue, Icons.Default.Timer),
    Sent("sent", QubeePalette.Cyan, Icons.Default.CheckCircle),
    Delivered("delivered", QubeePalette.Green, Icons.Default.VerifiedUser),
    Failed("failed", QubeePalette.Danger, Icons.Default.ErrorOutline),
    Received("received", QubeePalette.MutedText, Icons.Default.Shield),
    Audio("audio", QubeePalette.Cyan, Icons.Default.GraphicEq),
}
