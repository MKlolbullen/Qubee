@Composable
fun OnboardingScreen(
    viewModel: OnboardingViewModel,
    onOnboardingComplete: () -> Unit
) {
    val state by viewModel.state.collectAsState()
    var nickname by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Välkommen till Qubee", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Text("Säker P2P-kommunikation utan mellanhänder.", style = MaterialTheme.typography.bodyMedium)

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedTextField(
            value = nickname,
            onValueChange = { nickname = it },
            label = { Text("Välj ett visningsnamn") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(24.dp))

        if (state is OnboardingState.Loading) {
            CircularProgressIndicator()
            Text("Genererar Post-Quantum nycklar...")
        } else {
            Button(
                onClick = { viewModel.createIdentity(nickname) },
                enabled = nickname.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Skapa Identitet")
            }
        }

        // Hantera navigation vid framgång
        LaunchedEffect(state) {
            if (state is OnboardingState.Success) {
                onOnboardingComplete()
            }
        }
    }
}
