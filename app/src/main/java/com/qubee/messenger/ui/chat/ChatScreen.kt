@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    contactName: String,
    onBackClick: () -> Unit,
    onAttachFile: () -> Unit,
    onRecordAudio: () -> Unit,
    onTakePhoto: () -> Unit
) {
    val messages by viewModel.messages.collectAsState()
    var inputText by remember { mutableStateOf("") }

    Scaffold(
        containerColor = QubeeDarkBg, // Mörk bakgrund
        topBar = {
            // Top Bar liknande Signal (Namn + Avatar)
            SmallTopAppBar(
                title = {
                    Column {
                        Text(contactName, color = QubeeTextPrimary)
                        Text("Säker P2P-anslutning", style = MaterialTheme.typography.bodySmall, color = QubeeAccent)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = QubeeTextPrimary)
                    }
                },
                colors = TopAppBarDefaults.smallTopAppBarColors(containerColor = QubeeSurface)
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
                modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
                reverseLayout = true
            ) {
                items(messages) { msg ->
                    MessageBubble(msg)
                }
            }

            // Input-område med Media-knappar
            InputBar(
                text = inputText,
                onTextChanged = { inputText = it },
                onSend = {
                    viewModel.sendMessage(contactName, inputText) // Använder ID/Namn
                    inputText = ""
                },
                onAttachFile = onAttachFile,
                onRecordAudio = onRecordAudio,
                onTakePhoto = onTakePhoto
            )
        }
    }
}

@Composable
fun InputBar(
    text: String,
    onTextChanged: (String) -> Unit,
    onSend: () -> Unit,
    onAttachFile: () -> Unit,
    onRecordAudio: () -> Unit,
    onTakePhoto: () -> Unit
) {
    Surface(
        color = QubeeSurface,
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier.padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Vänster: Media-knappar (Dold under "+" eller synliga)
            IconButton(onClick = onAttachFile) {
                Icon(Icons.Default.AttachFile, "Filer", tint = QubeeTextSecondary)
            }

            // Textfält (Mjukare hörn som i moderna chatt-appar)
            TextField(
                value = text,
                onValueChange = onTextChanged,
                modifier = Modifier.weight(1f).padding(horizontal = 4.dp),
                shape = RoundedCornerShape(24.dp),
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = Color.Black.copy(alpha = 0.3f),
                    unfocusedContainerColor = Color.Black.copy(alpha = 0.3f),
                    focusedTextColor = QubeeTextPrimary,
                    unfocusedTextColor = QubeeTextPrimary,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent
                ),
                placeholder = { Text("Meddelande...", color = QubeeTextSecondary) },
                maxLines = 4
            )

            // Höger: Kamera/Mic eller Skicka
            if (text.isBlank()) {
                IconButton(onClick = onTakePhoto) {
                    Icon(Icons.Default.CameraAlt, "Kamera", tint = QubeeTextSecondary)
                }
                IconButton(onClick = onRecordAudio) {
                    Icon(Icons.Default.Mic, "Ljud", tint = QubeeTextSecondary)
                }
            } else {
                IconButton(
                    onClick = onSend,
                    colors = IconButtonDefaults.iconButtonColors(contentColor = QubeeAccent)
                ) {
                    Icon(Icons.Default.Send, "Skicka")
                }
            }
        }
    }
}