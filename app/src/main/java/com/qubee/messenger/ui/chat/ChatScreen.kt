package com.qubee.messenger.ui.chat

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
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
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanelBorder
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQuantumBrush
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    onBackClick: () -> Unit,
) {
    QubeeTheme {
        val uiState by viewModel.uiState.collectAsState()
        val snackbarHostState = remember { SnackbarHostState() }
        var inputText by remember { mutableStateOf("") }
        var showDetails by remember { mutableStateOf(false) }

        LaunchedEffect(viewModel) {
            viewModel.events.collect { event ->
                when (event) {
                    is ChatUiEvent.Notice -> snackbarHostState.showSnackbar(event.message)
                }
            }
        }

        Scaffold(
            containerColor = QubeePalette.Void,
            snackbarHost = { SnackbarHost(snackbarHostState) },
            topBar = {
                SecureChatTopBar(
                    contactName = uiState.contactName,
                    securityState = uiState.securityState,
                    onBackClick = onBackClick,
                    onSecureCallClick = viewModel::requestSecureCall,
                    onDetailsClick = { showDetails = true },
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
            ChatWallpaper(modifier = Modifier.padding(padding)) {
                Column(modifier = Modifier.fillMaxSize()) {
                    SecurityBanner(uiState.securityState)
                    if (uiState.messages.isEmpty()) {
                        EmptyChatState(contactName = uiState.contactName)
                    } else {
                        LazyColumn(
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 10.dp),
                            reverseLayout = true,
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            items(uiState.messages.reversed(), key = { it.id }) { msg ->
                                MessageItem(msg)
                            }
                        }
                    }
                }
            }
        }

        if (showDetails) {
            ConversationDetailsSheet(
                contactName = uiState.contactName,
                securityState = uiState.securityState,
                details = uiState.details,
                onDismiss = { showDetails = false },
                onVerifyClick = viewModel::requestContactVerification,
                onTimerClick = viewModel::changeDisappearingTimer,
                onClearChatClick = {
                    showDetails = false
                    viewModel.clearChat()
                },
                onResetSessionClick = viewModel::resetSecureSession,
            )
        }
    }
}

@Composable
private fun ChatWallpaper(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Surface(color = QubeePalette.Void) {
        Box(
            modifier = modifier
                .fillMaxSize()
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            QubeePalette.Blue.copy(alpha = 0.15f),
                            QubeePalette.Cyan.copy(alpha = 0.05f),
                            Color.Transparent,
                        ),
                        center = Offset(850f, 50f),
                        radius = 1000f,
                    ),
                )
                .drawBehind {
                    val step = 68.dp.toPx()
                    var x = -step
                    while (x < size.width + step) {
                        var y = -step
                        while (y < size.height + step) {
                            drawCircle(
                                color = QubeePalette.Cyan.copy(alpha = 0.025f),
                                radius = 1.6.dp.toPx(),
                                center = Offset(x, y),
                            )
                            drawCircle(
                                color = QubeePalette.Green.copy(alpha = 0.018f),
                                radius = 18.dp.toPx(),
                                center = Offset(x + step * 0.5f, y + step * 0.42f),
                                style = androidx.compose.ui.graphics.drawscope.Stroke(width = 1f),
                            )
                            y += step
                        }
                        x += step
                    }
                },
        ) {
            content()
        }
    }
}

@Composable
private fun SecureChatTopBar(
    contactName: String,
    securityState: ConversationSecurityState,
    onBackClick: () -> Unit,
    onSecureCallClick: () -> Unit,
    onDetailsClick: () -> Unit,
) {
    Surface(
        color = Color(0xFF111815).copy(alpha = 0.98f),
        border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.18f)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 4.dp, end = 6.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBackClick) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = QubeePalette.Text)
            }
            PeerAvatar(contactName)
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = contactName,
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.headlineSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = securityState.icon,
                        contentDescription = null,
                        tint = securityState.color,
                        modifier = Modifier.size(13.dp),
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
            IconButton(onClick = onSecureCallClick) {
                Icon(Icons.Default.Lock, contentDescription = "Secure call", tint = QubeePalette.Cyan)
            }
            IconButton(onClick = onDetailsClick) {
                Icon(Icons.Default.MoreVert, contentDescription = "Conversation details", tint = QubeePalette.MutedText)
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
        modifier = Modifier.size(48.dp),
        shape = CircleShape,
        color = QubeePalette.Cyan.copy(alpha = 0.14f),
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
            .padding(horizontal = 10.dp, vertical = 8.dp),
        shape = RoundedCornerShape(18.dp),
        color = Color.Black.copy(alpha = 0.34f),
        border = BorderStroke(1.dp, securityState.color.copy(alpha = 0.34f)),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = securityState.icon,
                contentDescription = null,
                tint = securityState.color,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = securityState.description,
                color = QubeePalette.MutedText,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            QubeeStatusPill(securityState.compactLabel)
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
                modifier = Modifier.size(84.dp),
                shape = CircleShape,
                color = QubeePalette.Cyan.copy(alpha = 0.10f),
                border = BorderStroke(1.dp, QubeeQuantumBrush),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = QubeePalette.Cyan, modifier = Modifier.size(32.dp))
                }
            }
            Spacer(Modifier.height(18.dp))
            Text("Secure channel ready", color = QubeePalette.Text, style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            QubeeMutedText(
                text = "Send the first encrypted message to $contactName. The ratchet does not judge.",
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun MessageItem(msg: UiMessage) {
    when (msg.type) {
        UiMessageType.TEXT -> MessageBubble(msg)
        UiMessageType.IMAGE -> MediaMessageCard(msg, Icons.Default.PhotoCamera, "Encrypted image")
        UiMessageType.FILE -> MediaMessageCard(msg, Icons.Default.InsertDriveFile, "Encrypted file")
        UiMessageType.AUDIO -> AudioMessageCard(msg)
    }
}

@Composable
fun MessageBubble(msg: UiMessage) {
    val align = if (msg.isFromMe) Alignment.End else Alignment.Start
    val bubbleBrush = if (msg.isFromMe) {
        Brush.linearGradient(colors = listOf(QubeePalette.Cyan.copy(alpha = 0.26f), QubeePalette.Green.copy(alpha = 0.11f)))
    } else {
        Brush.linearGradient(colors = listOf(Color(0xFF262B29).copy(alpha = 0.96f), Color(0xFF1C2220).copy(alpha = 0.96f)))
    }
    val shape = if (msg.isFromMe) RoundedCornerShape(22.dp, 22.dp, 4.dp, 22.dp) else RoundedCornerShape(22.dp, 22.dp, 22.dp, 4.dp)
    val width = if (msg.text.length > 120) 0.90f else 0.76f

    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = align) {
        Surface(
            color = Color.Transparent,
            shape = shape,
            border = BorderStroke(
                width = 1.dp,
                brush = if (msg.isFromMe) QubeePanelBorder else Brush.linearGradient(
                    listOf(QubeePalette.Cyan.copy(alpha = 0.14f), QubeePalette.Green.copy(alpha = 0.08f)),
                ),
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth(width)
                    .background(bubbleBrush)
                    .padding(start = 14.dp, end = 10.dp, top = 9.dp, bottom = 7.dp),
            ) {
                Text(text = msg.text, color = QubeePalette.Text, style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.height(6.dp))
                MessageMeta(msg)
            }
        }
    }
}

@Composable
private fun MediaMessageCard(msg: UiMessage, icon: ImageVector, title: String) {
    val align = if (msg.isFromMe) Alignment.End else Alignment.Start
    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = align) {
        Surface(
            modifier = Modifier.fillMaxWidth(0.82f),
            shape = RoundedCornerShape(24.dp),
            color = Color(0xFF222725).copy(alpha = 0.96f),
            border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.22f)),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(156.dp)
                        .clip(RoundedCornerShape(18.dp))
                        .background(
                            Brush.linearGradient(
                                listOf(QubeePalette.Cyan.copy(alpha = 0.24f), QubeePalette.Green.copy(alpha = 0.10f), Color.Black.copy(alpha = 0.18f)),
                            ),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(imageVector = icon, contentDescription = null, tint = QubeePalette.Cyan, modifier = Modifier.size(46.dp))
                }
                Spacer(Modifier.height(10.dp))
                Text(title, color = QubeePalette.Text, style = MaterialTheme.typography.titleMedium)
                QubeeMutedText(msg.text.ifBlank { "Tap to decrypt preview" })
                Spacer(Modifier.height(8.dp))
                MessageMeta(msg)
            }
        }
    }
}

@Composable
private fun AudioMessageCard(msg: UiMessage) {
    val align = if (msg.isFromMe) Alignment.End else Alignment.Start
    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = align) {
        Surface(
            modifier = Modifier.fillMaxWidth(0.82f),
            shape = RoundedCornerShape(24.dp),
            color = Color(0xFF252A27).copy(alpha = 0.98f),
            border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.22f)),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(modifier = Modifier.size(58.dp), shape = RoundedCornerShape(18.dp), color = QubeePalette.Green.copy(alpha = 0.72f)) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Play", tint = QubeePalette.Void)
                        }
                    }
                    Spacer(Modifier.width(14.dp))
                    AudioWaveform(modifier = Modifier.weight(1f))
                    Spacer(Modifier.width(10.dp))
                    Text("00:00", color = QubeePalette.Text, style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(Modifier.height(9.dp))
                MessageMeta(msg.copy(status = MessageDeliveryState.Audio))
            }
        }
    }
}

@Composable
private fun AudioWaveform(modifier: Modifier = Modifier) {
    Row(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
        val bars = listOf(18, 34, 48, 28, 12, 22, 40, 54, 30, 16, 38, 46, 20)
        bars.forEach { height ->
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .height(height.dp)
                    .clip(RoundedCornerShape(999.dp))
                    .background(QubeePalette.Text.copy(alpha = 0.88f)),
            )
        }
    }
}

@Composable
private fun MessageMeta(msg: UiMessage) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
        Icon(imageVector = msg.status.icon, contentDescription = msg.status.label, tint = msg.status.color, modifier = Modifier.size(13.dp))
        Spacer(Modifier.width(4.dp))
        Text(text = formatMessageTime(msg.timestamp), color = QubeePalette.MutedText, style = MaterialTheme.typography.bodySmall)
        if (msg.isFromMe) {
            Spacer(Modifier.width(6.dp))
            Text(text = msg.status.label, color = msg.status.color, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
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
    Surface(color = Color.Transparent) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .imePadding()
                .padding(horizontal = 10.dp, vertical = 8.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(28.dp),
                    color = Color(0xFF111815).copy(alpha = 0.98f),
                    border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.16f)),
                ) {
                    Row(modifier = Modifier.padding(start = 4.dp, end = 8.dp, top = 4.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = onCamera) { Icon(Icons.Default.CameraAlt, "Camera", tint = QubeePalette.Text) }
                        TextField(
                            value = text,
                            onValueChange = onTextChanged,
                            modifier = Modifier.weight(1f),
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                                focusedTextColor = QubeePalette.Text,
                                unfocusedTextColor = QubeePalette.Text,
                                cursorColor = QubeePalette.Cyan,
                                focusedIndicatorColor = Color.Transparent,
                                unfocusedIndicatorColor = Color.Transparent,
                            ),
                            placeholder = { Text("Message", color = QubeePalette.MutedText) },
                            maxLines = 5,
                        )
                        IconButton(onClick = onAttach) { Icon(Icons.Default.AttachFile, "Attach file", tint = QubeePalette.Text) }
                    }
                }

                Spacer(Modifier.width(8.dp))

                IconButton(
                    onClick = if (text.isBlank()) onMic else onSend,
                    modifier = Modifier
                        .size(58.dp)
                        .background(brush = QubeeQuantumBrush, shape = CircleShape),
                ) {
                    Icon(
                        imageVector = if (text.isBlank()) Icons.Default.Mic else Icons.Default.Send,
                        contentDescription = if (text.isBlank()) "Record audio" else "Send",
                        tint = QubeePalette.Void,
                        modifier = Modifier.size(28.dp),
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConversationDetailsSheet(
    contactName: String,
    securityState: ConversationSecurityState,
    details: ConversationDetailsUi,
    onDismiss: () -> Unit,
    onVerifyClick: () -> Unit,
    onTimerClick: () -> Unit,
    onClearChatClick: () -> Unit,
    onResetSessionClick: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF0B1516),
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
                color = QubeePalette.Cyan.copy(alpha = 0.35f),
            ) {}

            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                PeerAvatar(contactName)
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = contactName,
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Black,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(securityState.icon, contentDescription = null, tint = securityState.color, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = securityState.label,
                            color = securityState.color,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }

            Spacer(Modifier.height(18.dp))

            DetailsSection(title = "Identity & trust") {
                DetailsRow("Fingerprint", details.fingerprint)
                DetailsRow("Verification", details.verificationLabel)
                Spacer(Modifier.height(12.dp))
                QubeePrimaryButton(text = "Verify contact", onClick = onVerifyClick)
            }

            Spacer(Modifier.height(12.dp))

            DetailsSection(title = "Session security") {
                DetailsRow("Session", details.sessionLabel)
                DetailsRow("Disappearing messages", details.disappearingTimerLabel)
                Spacer(Modifier.height(8.dp))
                QubeeMutedText(details.sessionNote)
                Spacer(Modifier.height(12.dp))
                QubeeSecondaryButton(text = "Change disappearing timer", onClick = onTimerClick)
            }

            Spacer(Modifier.height(12.dp))

            DetailsSection(title = "Media & files") {
                DetailsRow("Media", details.mediaCount.toString())
                DetailsRow("Files", details.fileCount.toString())
                DetailsRow("Voice notes", details.audioCount.toString())
            }

            Spacer(Modifier.height(12.dp))

            DetailsSection(title = "Danger zone") {
                QubeeSecondaryButton(text = "Clear local chat", onClick = onClearChatClick)
                Spacer(Modifier.height(10.dp))
                DangerButton(text = "Reset secure session", onClick = onResetSessionClick)
            }

            Spacer(Modifier.height(18.dp))
        }
    }
}

@Composable
private fun DetailsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = Color(0xFF101B1C).copy(alpha = 0.95f),
        border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.16f)),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(text = title, color = QubeePalette.Text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
private fun DetailsRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Text(text = label, color = QubeePalette.MutedText, style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.width(12.dp))
        Text(
            text = value,
            color = QubeePalette.Text,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun DangerButton(text: String, onClick: () -> Unit) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        color = Color(0xFF3A1018),
        border = BorderStroke(1.dp, QubeePalette.Danger.copy(alpha = 0.55f)),
    ) {
        Box(modifier = Modifier.padding(vertical = 14.dp), contentAlignment = Alignment.Center) {
            Text(text = text, color = Color(0xFFFFB3C1), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
    }
}

private fun formatMessageTime(timestamp: Long): String {
    if (timestamp <= 0L) return "now"
    return SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(timestamp))
}

enum class ConversationSecurityState(
    val label: String,
    val compactLabel: String,
    val description: String,
    val color: Color,
    val icon: ImageVector,
) {
    PqSessionActive(
        label = "PQ session active",
        compactLabel = "PQ READY",
        description = "Hybrid post-quantum session active. Verify fingerprint before high-trust use.",
        color = QubeePalette.Cyan,
        icon = Icons.Default.VerifiedUser,
    ),
    Unverified(
        label = "Unverified contact",
        compactLabel = "VERIFY",
        description = "Encrypted, but identity is not manually verified yet.",
        color = QubeePalette.Warning,
        icon = Icons.Default.ErrorOutline,
    ),
    OfflineQueued(
        label = "Offline queue",
        compactLabel = "QUEUED",
        description = "Messages encrypt locally and send when the P2P path returns.",
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
