package com.qubee.messenger.ui.chat

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Divider
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.R
import com.qubee.messenger.transfer.FileTransfer
import com.qubee.messenger.ui.contacts.verification.ContactVerificationActivity
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeDangerButton
import com.qubee.messenger.ui.theme.QubeeIconButton
import com.qubee.messenger.ui.theme.QubeeMono
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.qubeeInitials
import com.qubee.messenger.util.shareText
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    onBackClick: () -> Unit,
) {
    QubeeTheme {
        val uiState by viewModel.uiState.collectAsStateWithLifecycle()
        val snackbarHostState = remember { SnackbarHostState() }
        var inputText by remember { mutableStateOf("") }
        var showDetails by remember { mutableStateOf(false) }
        val context = LocalContext.current
        val noPeerIdentity = stringResource(R.string.chat_no_peer_identity)
        var pendingVideoSession by remember { mutableStateOf(false) }
        val microphonePermission = rememberLauncherForActivityResult(
            ActivityResultContracts.RequestPermission(),
        ) { granted -> if (granted) viewModel.requestSecureCall(pendingVideoSession) }
        val startSession = { video: Boolean ->
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                viewModel.requestSecureCall(video)
            } else {
                pendingVideoSession = video
                microphonePermission.launch(Manifest.permission.RECORD_AUDIO)
            }
        }
        val filePicker = rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocument(),
        ) { uri -> uri?.let(viewModel::sendSelectedFile) }

        // One confirm screen for the whole app: the chat hands the peer's
        // identity to it and the contact flow brings the result back.
        val openConfirm = {
            val peer = uiState.peerIdentityIdHex
            if (peer == null) {
                viewModel.notice(noPeerIdentity)
            } else {
                context.startActivity(ContactVerificationActivity.createIntent(context, peer))
            }
        }

        LaunchedEffect(viewModel) {
            viewModel.events.collect { event ->
                when (event) {
                    is ChatUiEvent.Notice -> snackbarHostState.showSnackbar(event.message)
                    is ChatUiEvent.ShareLink -> shareText(context, event.link, event.title)
                }
            }
        }

        ChatContent(
            uiState = uiState,
            inputText = inputText,
            onTextChanged = { inputText = it },
            onSend = {
                viewModel.sendMessage(inputText)
                inputText = ""
            },
            onAttach = { filePicker.launch(arrayOf("*/*")) },
            onBackClick = onBackClick,
            onSecurityClick = { if (uiState.isGroup) showDetails = true else openConfirm() },
            onSecureCallClick = { startSession(false) },
            onSecureVideoClick = { startSession(true) },
            onDetailsClick = { showDetails = true },
            snackbarHostState = snackbarHostState,
        )

        if (showDetails) {
            if (uiState.isGroup) {
                GroupDetailsSheet(
                    groupName = uiState.contactName,
                    members = uiState.groupMembers,
                    myIdentityIdHex = uiState.myIdentityIdHex,
                    onLoadMembers = viewModel::loadGroupMembers,
                    onAddMember = viewModel::addMember,
                    onRemoveMember = viewModel::removeMember,
                    onPromoteMember = viewModel::promoteMember,
                    onTransferOwnership = viewModel::transferOwnership,
                    onLeaveGroup = viewModel::leaveGroup,
                    onDismiss = { showDetails = false },
                )
            } else {
                ConversationDetailsSheet(
                    contactName = uiState.contactName,
                    securityState = uiState.securityState,
                    details = uiState.details,
                    onDismiss = { showDetails = false },
                    onVerifyClick = {
                        showDetails = false
                        openConfirm()
                    },
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
}

/** The chat itself, stateless so Paparazzi can render it from a fabricated [ChatUiState]. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun ChatContent(
    uiState: ChatUiState,
    inputText: String,
    onTextChanged: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
    onBackClick: () -> Unit,
    onSecurityClick: () -> Unit,
    onSecureCallClick: () -> Unit,
    onSecureVideoClick: () -> Unit,
    onDetailsClick: () -> Unit,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        containerColor = QubeePalette.Void,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            SecureChatTopBar(
                contactName = uiState.contactName,
                securityState = uiState.securityState,
                isGroup = uiState.isGroup,
                onBackClick = onBackClick,
                onSecurityClick = onSecurityClick,
                onSecureCallClick = onSecureCallClick,
                onSecureVideoClick = onSecureVideoClick,
                callingAvailable = uiState.callingAvailable && !uiState.isGroup,
                onDetailsClick = onDetailsClick,
            )
        },
        bottomBar = {
            ChatInputBar(
                text = inputText,
                onTextChanged = onTextChanged,
                onSend = onSend,
                onAttach = onAttach,
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .background(QubeePalette.Void),
        ) {
            SecurityBanner(uiState.securityState)
            if (uiState.messages.isEmpty()) {
                EmptyChatState(contactName = uiState.contactName)
            } else {
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .padding(horizontal = 16.dp),
                    reverseLayout = true,
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(uiState.messages.reversed(), key = { it.id }) { msg ->
                        MessageItem(msg, isGroup = uiState.isGroup)
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
    isGroup: Boolean,
    onBackClick: () -> Unit,
    onSecurityClick: () -> Unit,
    onSecureCallClick: () -> Unit,
    onSecureVideoClick: () -> Unit,
    callingAvailable: Boolean,
    onDetailsClick: () -> Unit,
) {
    Surface(color = QubeePalette.Void2) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 4.dp, end = 6.dp, top = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onBackClick, modifier = Modifier.size(44.dp)) {
                    Icon(Icons.Filled.ArrowBack, contentDescription = stringResource(R.string.chat_back), tint = QubeePalette.Text)
                }
                if (isGroup) {
                    QubeeAvatar(initials = "", size = 40.dp, icon = Icons.Outlined.Group, color = QubeePalette.MutedText)
                } else {
                    QubeeAvatar(initials = contactName.qubeeInitials(), size = 40.dp)
                }
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = contactName,
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.titleLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Row(
                        modifier = Modifier
                            .clickable(onClick = onSecurityClick)
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
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
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                // Absent unless this build's native library was compiled with
                // `--features calling` AND `startCalling()` linked the symbols.
                // A call icon on the default .so would imply a capability that
                // fails closed.
                if (callingAvailable) {
                    IconButton(onClick = onSecureCallClick) {
                        Icon(Icons.Filled.Call, contentDescription = stringResource(R.string.chat_voice_call), tint = QubeePalette.Cyan)
                    }
                    IconButton(onClick = onSecureVideoClick) {
                        Icon(Icons.Filled.Videocam, contentDescription = stringResource(R.string.chat_video_call), tint = QubeePalette.Cyan)
                    }
                }
                IconButton(onClick = onDetailsClick) {
                    Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.chat_details), tint = QubeePalette.MutedText)
                }
            }
            Divider(color = QubeePalette.PanelAlt)
        }
    }
}

@Composable
private fun SecurityBanner(securityState: ConversationSecurityState) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Surface(
            shape = RoundedCornerShape(14.dp),
            color = QubeePalette.Panel,
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Icon(
                    imageVector = Icons.Outlined.Lock,
                    contentDescription = null,
                    tint = securityState.color,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(10.dp))
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
                .padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            QubeeAvatar(initials = "", size = 72.dp, icon = Icons.Outlined.Lock)
            Spacer(Modifier.height(18.dp))
            Text(stringResource(R.string.chat_empty_title), color = QubeePalette.Text, style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.chat_empty_body, contactName),
                color = QubeePalette.MutedText,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun MessageItem(msg: UiMessage, isGroup: Boolean) {
    val context = LocalContext.current
    // Only incoming group messages get a sender line: a 1:1 chat
    // already names the peer in the top bar, and our own bubbles
    // sit on the other edge of the screen.
    val showSender = isGroup && !msg.isFromMe && msg.senderName.isNotBlank()
    when (msg.type) {
        UiMessageType.TEXT -> MessageBubble(msg, showSender)
        UiMessageType.IMAGE -> MediaMessageCard(msg, Icons.Filled.PhotoCamera, "Encrypted image", showSender)
        UiMessageType.FILE -> MediaMessageCard(
            msg,
            Icons.Filled.InsertDriveFile,
            "Encrypted file",
            showSender,
            onClick = { FileTransfer.open(context, msg.id, msg.text) },
        )
        UiMessageType.AUDIO -> AudioMessageCard(msg, showSender)
    }
}

@Composable
private fun SenderLabel(name: String, onAccent: Boolean) {
    Text(
        text = name,
        color = if (onAccent) QubeePalette.Void else QubeePalette.Cyan,
        style = MaterialTheme.typography.labelMedium,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

private fun bubbleShape(fromMe: Boolean) =
    if (fromMe) RoundedCornerShape(18.dp, 18.dp, 6.dp, 18.dp) else RoundedCornerShape(18.dp, 18.dp, 18.dp, 6.dp)

@Composable
fun MessageBubble(msg: UiMessage, showSender: Boolean = false) {
    val fromMe = msg.isFromMe
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (fromMe) Alignment.End else Alignment.Start,
    ) {
        Surface(
            shape = bubbleShape(fromMe),
            color = if (fromMe) QubeePalette.Cyan else QubeePalette.PanelAlt,
            modifier = Modifier.widthIn(max = 300.dp),
        ) {
            Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                if (showSender) SenderLabel(msg.senderName, onAccent = fromMe)
                Text(
                    text = msg.text,
                    color = if (fromMe) QubeePalette.Void else QubeePalette.Text,
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
        Spacer(Modifier.height(4.dp))
        MessageMeta(msg)
    }
}

@Composable
private fun MediaMessageCard(
    msg: UiMessage,
    icon: ImageVector,
    title: String,
    showSender: Boolean = false,
    onClick: (() -> Unit)? = null,
) {
    val fromMe = msg.isFromMe
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (fromMe) Alignment.End else Alignment.Start,
    ) {
        Surface(
            modifier = Modifier
                .widthIn(min = 220.dp, max = 300.dp)
                .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
            shape = bubbleShape(fromMe),
            color = if (fromMe) QubeePalette.Cyan else QubeePalette.PanelAlt,
        ) {
            Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                if (showSender) {
                    SenderLabel(msg.senderName, onAccent = fromMe)
                    Spacer(Modifier.height(6.dp))
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(
                                if (fromMe) QubeePalette.Void.copy(alpha = 0.18f) else QubeePalette.Panel,
                                RoundedCornerShape(10.dp),
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = if (fromMe) QubeePalette.Void else QubeePalette.Cyan,
                            modifier = Modifier.size(22.dp),
                        )
                    }
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(
                            text = msg.text.ifBlank { title },
                            color = if (fromMe) QubeePalette.Void else QubeePalette.Text,
                            style = MaterialTheme.typography.titleSmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "$title · encrypted on your phone",
                            color = if (fromMe) QubeePalette.Void.copy(alpha = 0.75f) else QubeePalette.MutedText,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        MessageMeta(msg)
    }
}

@Composable
private fun AudioMessageCard(msg: UiMessage, showSender: Boolean = false) {
    val fromMe = msg.isFromMe
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (fromMe) Alignment.End else Alignment.Start,
    ) {
        Surface(
            modifier = Modifier.widthIn(min = 220.dp, max = 300.dp),
            shape = bubbleShape(fromMe),
            color = if (fromMe) QubeePalette.Cyan else QubeePalette.PanelAlt,
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                if (showSender) {
                    SenderLabel(msg.senderName, onAccent = fromMe)
                    Spacer(Modifier.height(6.dp))
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(
                                if (fromMe) QubeePalette.Void.copy(alpha = 0.18f) else QubeePalette.Panel,
                                CircleShape,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            Icons.Filled.PlayArrow,
                            contentDescription = "Play",
                            tint = if (fromMe) QubeePalette.Void else QubeePalette.Cyan,
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    AudioWaveform(
                        modifier = Modifier.weight(1f),
                        color = if (fromMe) QubeePalette.Void.copy(alpha = 0.6f) else QubeePalette.MutedText,
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        "00:00",
                        color = if (fromMe) QubeePalette.Void else QubeePalette.Text,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = QubeeMono,
                    )
                }
            }
        }
        Spacer(Modifier.height(4.dp))
        MessageMeta(msg.copy(status = MessageDeliveryState.Audio))
    }
}

@Composable
private fun AudioWaveform(modifier: Modifier = Modifier, color: Color) {
    Row(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(3.dp), verticalAlignment = Alignment.CenterVertically) {
        val bars = listOf(10, 18, 26, 14, 8, 12, 22, 28, 16, 9, 20, 24, 11)
        bars.forEach { height ->
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .height(height.dp)
                    .background(color, RoundedCornerShape(999.dp)),
            )
        }
    }
}

@Composable
private fun MessageMeta(msg: UiMessage) {
    Row(
        modifier = Modifier.padding(horizontal = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = formatMessageTime(msg.timestamp),
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.bodySmall,
        )
        if (msg.isFromMe) {
            Spacer(Modifier.width(5.dp))
            Icon(
                imageVector = msg.status.icon,
                contentDescription = null,
                tint = msg.status.color,
                modifier = Modifier.size(13.dp),
            )
            Spacer(Modifier.width(3.dp))
            Text(
                text = msg.status.label,
                color = msg.status.color,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
fun ChatInputBar(
    text: String,
    onTextChanged: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
) {
    val canSend = text.isNotBlank()
    Surface(color = QubeePalette.Void2) {
        Column {
            Divider(color = QubeePalette.PanelAlt)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .imePadding()
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                QubeeIconButton(
                    icon = Icons.Filled.Add,
                    contentDescription = stringResource(R.string.chat_attach),
                    onClick = onAttach,
                )
                Spacer(Modifier.width(10.dp))
                TextField(
                    value = text,
                    onValueChange = onTextChanged,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(24.dp),
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = QubeePalette.Panel,
                        unfocusedContainerColor = QubeePalette.Panel,
                        focusedTextColor = QubeePalette.Text,
                        unfocusedTextColor = QubeePalette.Text,
                        cursorColor = QubeePalette.Cyan,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                        disabledIndicatorColor = Color.Transparent,
                    ),
                    placeholder = { Text(stringResource(R.string.chat_message_placeholder), color = QubeePalette.MutedText) },
                    maxLines = 5,
                )
                Spacer(Modifier.width(10.dp))
                IconButton(
                    onClick = onSend,
                    enabled = canSend,
                    modifier = Modifier
                        .size(46.dp)
                        .background(if (canSend) QubeePalette.Cyan else QubeePalette.PanelAlt, CircleShape),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Send,
                        contentDescription = stringResource(R.string.chat_send),
                        tint = if (canSend) QubeePalette.Void else QubeePalette.MutedText,
                        modifier = Modifier.size(22.dp),
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
                QubeeAvatar(initials = contactName.qubeeInitials())
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
                        Icon(securityState.icon, contentDescription = null, tint = securityState.color, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = securityState.label,
                            color = securityState.color,
                            style = MaterialTheme.typography.labelMedium,
                        )
                    }
                }
            }

            Spacer(Modifier.height(18.dp))

            DetailsSection(title = stringResource(R.string.chat_details_identity)) {
                DetailsRow(stringResource(R.string.chat_details_fingerprint), details.fingerprint)
                DetailsRow(stringResource(R.string.chat_details_checked), details.verificationLabel)
                Spacer(Modifier.height(12.dp))
                QubeePrimaryButton(text = stringResource(R.string.chat_details_confirm, contactName), onClick = onVerifyClick)
            }

            Spacer(Modifier.height(12.dp))

            DetailsSection(title = stringResource(R.string.chat_details_session)) {
                DetailsRow(stringResource(R.string.chat_details_session), details.sessionLabel)
                DetailsRow(stringResource(R.string.chat_details_disappearing), details.disappearingTimerLabel)
                Spacer(Modifier.height(8.dp))
                QubeeMutedText(details.sessionNote, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
                QubeeSecondaryButton(text = stringResource(R.string.chat_details_change_timer), onClick = onTimerClick)
            }

            Spacer(Modifier.height(12.dp))

            DetailsSection(title = stringResource(R.string.chat_details_media)) {
                DetailsRow(stringResource(R.string.chat_details_media_count), details.mediaCount.toString())
                DetailsRow(stringResource(R.string.chat_details_file_count), details.fileCount.toString())
                DetailsRow(stringResource(R.string.chat_details_audio_count), details.audioCount.toString())
            }

            Spacer(Modifier.height(12.dp))

            DetailsSection(title = stringResource(R.string.chat_details_careful)) {
                QubeeSecondaryButton(text = stringResource(R.string.chat_details_clear), onClick = onClearChatClick)
                Spacer(Modifier.height(10.dp))
                QubeeDangerButton(text = stringResource(R.string.chat_details_reset), onClick = onResetSessionClick)
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
        shape = RoundedCornerShape(16.dp),
        color = QubeePalette.Void2,
        border = BorderStroke(1.dp, QubeePalette.PanelAlt),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(text = title, color = QubeePalette.Text, style = MaterialTheme.typography.titleMedium)
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

private fun formatMessageTime(timestamp: Long): String {
    if (timestamp <= 0L) return "now"
    return SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(timestamp))
}

/**
 * What the header and the strip above the thread say about a chat.
 * Plain words only: the user needs to know whether it is private and
 * whether they have checked who is on the other end. A changed key is
 * its own state, never a flavour of "confirmed", per TrustStatePolicy.
 */
enum class ConversationSecurityState(
    val label: String,
    val compactLabel: String,
    val description: String,
    val color: Color,
    val icon: ImageVector,
) {
    PqSessionActive(
        label = "Private · Not confirmed yet",
        compactLabel = "PRIVATE",
        description = "Messages here are locked end to end with post-quantum keys. Confirm the short code together once to be sure nobody is in between.",
        color = QubeePalette.MutedText,
        icon = Icons.Outlined.Shield,
    ),
    Verified(
        label = "Private · Confirmed in person",
        compactLabel = "CONFIRMED",
        description = "Messages here are locked end to end, and you have confirmed who is on the other side.",
        color = QubeePalette.Green,
        icon = Icons.Filled.GppGood,
    ),
    Unverified(
        label = "Private · Not confirmed yet",
        compactLabel = "PRIVATE",
        description = "Messages here are locked end to end. A post-quantum session starts once both phones have exchanged keys.",
        color = QubeePalette.MutedText,
        icon = Icons.Outlined.Shield,
    ),
    KeyChanged(
        label = "Safety key changed · Tap to check",
        compactLabel = "CHECK",
        description = "This contact's safety key changed. That happens when they reset Qubee, but also if someone is in between. Confirm the short code together before trusting new messages.",
        color = QubeePalette.Warning,
        icon = Icons.Filled.GppMaybe,
    ),
    OfflineQueued(
        label = "Offline · sends when back in reach",
        compactLabel = "OFFLINE",
        description = "Messages are locked on your phone now and sent as soon as the other phone can be reached.",
        color = QubeePalette.Blue,
        icon = Icons.Filled.Timer,
    ),
}

enum class MessageDeliveryState(
    val label: String,
    val color: Color,
    val icon: ImageVector,
) {
    Encrypting("Sending", QubeePalette.MutedText, Icons.Filled.Lock),
    Queued("Waiting", QubeePalette.Blue, Icons.Filled.Timer),
    Sent("Sent", QubeePalette.MutedText, Icons.Filled.CheckCircle),
    Delivered("Delivered", QubeePalette.Green, Icons.Filled.GppGood),
    Failed("Failed", QubeePalette.Danger, Icons.Filled.ErrorOutline),
    Received("Received", QubeePalette.MutedText, Icons.Outlined.Shield),
    Audio("Voice note", QubeePalette.MutedText, Icons.Filled.GraphicEq),
}
