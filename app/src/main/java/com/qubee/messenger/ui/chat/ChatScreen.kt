package com.qubee.messenger.ui.chat

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// Tema-färger för "Secure Dark Mode"
val QubeeDarkBg = Color(0xFF121212)
val QubeeSurface = Color(0xFF1E1E1E)
val QubeeMyBubble = Color(0xFF2C6836) // Dämpad grön
val QubeeTheirBubble = Color(0xFF2A2A2A) // Mörkgrå
val QubeeTextPrimary = Color(0xFFEEEEEE)
val QubeeTextSecondary = Color(0xFFAAAAAA)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    onBackClick: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsState()
    var inputText by remember { mutableStateOf("") }

    Scaffold(
        containerColor = QubeeDarkBg,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(uiState.contactName, color = QubeeTextPrimary)
                        Text("Secure P2P-connection", fontSize = 12.sp, color = Color.Green)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = QubeeTextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = QubeeSurface)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
        ) {
            // Meddelandelista
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 8.dp),
                reverseLayout = true // Senaste meddelandet längst ner
            ) {
                items(uiState.messages.reversed()) { msg ->
                    MessageBubble(msg)
                }
            }

            // Inputfält
            ChatInputBar(
                text = inputText,
                onTextChanged = { inputText = it },
                onSend = {
                    viewModel.sendMessage(inputText)
                    inputText = ""
                },
                onAttach = viewModel::onAttachFile,
                onCamera = viewModel::onTakePhoto,
                onMic = viewModel::onRecordAudio
            )
        }
    }
}

@Composable
fun MessageBubble(msg: UiMessage) {
    val align = if (msg.isFromMe) Alignment.End else Alignment.Start
    val color = if (msg.isFromMe) QubeeMyBubble else QubeeTheirBubble
    val shape = if (msg.isFromMe) {
        RoundedCornerShape(16.dp, 16.dp, 2.dp, 16.dp)
    } else {
        RoundedCornerShape(16.dp, 16.dp, 16.dp, 2.dp)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalAlignment = align
    ) {
        Surface(
            color = color,
            shape = shape,
            shadowElevation = 1.dp
        ) {
            Text(
                text = msg.text,
                modifier = Modifier.padding(12.dp),
                color = QubeeTextPrimary,
                style = MaterialTheme.typography.bodyLarge
            )
        }
        Text(
            text = "14:20", // Placeholder timestamp format
            style = MaterialTheme.typography.labelSmall,
            color = QubeeTextSecondary,
            modifier = Modifier.padding(top = 2.dp, start = 4.dp, end = 4.dp)
        )
    }
}

@Composable
fun ChatInputBar(
    text: String,
    onTextChanged: (String) -> Unit,
    onSend: () -> Unit,
    onAttach: () -> Unit,
    onCamera: () -> Unit,
    onMic: () -> Unit
) {
    Surface(
        color = QubeeSurface,
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier
                .padding(8.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Media Actions
            IconButton(onClick = onAttach) { Icon(Icons.Default.AttachFile, "Fil", tint = QubeeTextSecondary) }
            
            // Text Input
            TextField(
                value = text,
                onValueChange = onTextChanged,
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 4.dp),
                shape = RoundedCornerShape(24.dp),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = Color.Black.copy(alpha = 0.3f),
                    unfocusedContainerColor = Color.Black.copy(alpha = 0.3f),
                    focusedTextColor = QubeeTextPrimary,
                    unfocusedTextColor = QubeeTextPrimary,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent
                ),
                placeholder = { Text("Enter message...", color = QubeeTextSecondary) },
                maxLines = 4
            )

            // Send or Media Actions
            if (text.isBlank()) {
                IconButton(onClick = onCamera) { Icon(Icons.Default.CameraAlt, "Camera", tint = QubeeTextSecondary) }
                IconButton(onClick = onMic) { Icon(Icons.Default.Mic, "Sound", tint = QubeeTextSecondary) }
            } else {
                IconButton(
                    onClick = onSend,
                    modifier = Modifier
                        .background(Color.Green.copy(alpha = 0.2f), CircleShape)
                        .padding(2.dp)
                ) {
                    Icon(Icons.Default.Send, "Send", tint = Color.Green)
                }
            }
        }
    }
}
