@Composable
fun ChatScreen(
    viewModel: ChatViewModel,
    sessionId: String,
    contactAddress: String, // T.ex. IP-adress eller Onion-adress
    onBackClick: () -> Unit
) {
    val messages by viewModel.messages.collectAsState()
    var inputText by remember { mutableStateOf("") }

    LaunchedEffect(sessionId) {
        viewModel.loadMessages(sessionId)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { 
                    Column {
                        Text("Direktansluten Kontakt")
                        Text(
                            text = "via $contactAddress", 
                            style = MaterialTheme.typography.bodySmall, 
                            color = Color.Gray
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Tillbaka")
                    }
                }
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
                modifier = Modifier.weight(1f),
                reverseLayout = true
            ) {
                items(messages) { msg ->
                    ChatBubble(message = msg)
                }
            }

            // Input fält
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Skriv ett krypterat meddelande...") },
                    maxLines = 3
                )
                
                IconButton(
                    onClick = {
                        if (inputText.isNotBlank()) {
                            viewModel.sendMessage(sessionId, contactAddress, inputText)
                            inputText = ""
                        }
                    },
                    enabled = inputText.isNotBlank()
                ) {
                    Icon(Icons.Default.Send, contentDescription = "Skicka")
                }
            }
        }
    }
}

@Composable
fun ChatBubble(message: UiMessage) {
    val align = if (message.isFromMe) Alignment.End else Alignment.Start
    val color = if (message.isFromMe) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.secondaryContainer

    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalAlignment = align
    ) {
        Surface(
            shape = MaterialTheme.shapes.medium,
            color = color,
            shadowElevation = 1.dp
        ) {
            Text(
                text = message.text,
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodyLarge
            )
        }
    }
}
