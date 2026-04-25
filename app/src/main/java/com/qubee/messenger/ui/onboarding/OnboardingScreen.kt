package com.qubee.messenger.ui.onboarding

import android.content.Intent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.util.QrUtils

@Composable
fun OnboardingScreen(
    viewModel: OnboardingViewModel,
    onOnboardingComplete: () -> Unit,
) {
    val state by viewModel.state.collectAsState()
    var nickname by remember { mutableStateOf("") }

    LaunchedEffect(state) {
        if (state is OnboardingState.Complete) onOnboardingComplete()
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        when (val s = state) {
            is OnboardingState.Success -> SuccessView(
                bundle = s.bundle,
                onDone = {
                    viewModel.acknowledge()
                    onOnboardingComplete()
                },
            )

            // Complete state: nothing to render — the LaunchedEffect above
            // takes care of navigation as soon as we land here.
            OnboardingState.Complete -> Unit

            else -> {
                Text("Welcome to Qubee", style = MaterialTheme.typography.headlineMedium)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Generate your post-quantum identity and share it via QR — your private key never leaves the device.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(32.dp))

                OutlinedTextField(
                    value = nickname,
                    onValueChange = { nickname = it },
                    label = { Text("Display name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                Spacer(Modifier.height(24.dp))

                if (s is OnboardingState.Loading) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(8.dp))
                    Text("Generating Kyber/Dilithium keys + ZK proof…")
                } else {
                    Button(
                        onClick = { viewModel.createIdentity(nickname) },
                        enabled = nickname.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Create identity") }
                }

                if (s is OnboardingState.Error) {
                    Spacer(Modifier.height(12.dp))
                    Text(s.message, color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
private fun SuccessView(
    bundle: IdentityBundle,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    val link = bundle.shareLink
    val bitmap = remember(link) { link?.let { QrUtils.encodeAsBitmap(it) } }

    Text("Identity ready", style = MaterialTheme.typography.headlineMedium)
    Spacer(Modifier.height(4.dp))
    Text(bundle.displayName, style = MaterialTheme.typography.titleMedium)
    Text("Fingerprint: ${bundle.fingerprint}", style = MaterialTheme.typography.bodySmall)

    Spacer(Modifier.height(16.dp))

    bitmap?.let {
        Image(
            bitmap = it.asImageBitmap(),
            contentDescription = "Your Qubee identity QR",
            modifier = Modifier.size(240.dp),
        )
    }

    Spacer(Modifier.height(8.dp))

    if (link != null) {
        Text(link, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = {
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, link)
                }
                context.startActivity(Intent.createChooser(intent, "Share Qubee identity"))
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Share link") }
    }

    Spacer(Modifier.height(16.dp))
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
        Text("Continue")
    }
}
