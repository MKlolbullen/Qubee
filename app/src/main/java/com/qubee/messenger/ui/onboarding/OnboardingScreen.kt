package com.qubee.messenger.ui.onboarding

import android.content.Intent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.ui.theme.QubeeHeroMark
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.util.QrUtils

@Composable
fun OnboardingScreen(
    viewModel: OnboardingViewModel,
    onOnboardingComplete: () -> Unit,
) {
    QubeeTheme {
        val state by viewModel.state.collectAsState()
        var nickname by remember { mutableStateOf("") }

        LaunchedEffect(state) {
            if (state is OnboardingState.Complete) onOnboardingComplete()
        }

        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 22.dp, vertical = 28.dp),
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

                    else -> IdentityBootstrapView(
                        state = s,
                        nickname = nickname,
                        onNicknameChange = { nickname = it },
                        onCreate = { viewModel.createIdentity(nickname.trim()) },
                    )
                }
            }
        }
    }
}

@Composable
private fun IdentityBootstrapView(
    state: OnboardingState,
    nickname: String,
    onNicknameChange: (String) -> Unit,
    onCreate: () -> Unit,
) {
    QubeeHeroMark()
    Spacer(Modifier.height(22.dp))

    QubeeStatusPill("POST-QUANTUM IDENTITY BOOTSTRAP")
    Spacer(Modifier.height(14.dp))

    Text(
        "Own your keys.\nOwn your graph.",
        color = QubeePalette.Text,
        style = MaterialTheme.typography.headlineLarge,
        fontWeight = FontWeight.Black,
    )
    Spacer(Modifier.height(10.dp))
    QubeeMutedText(
        "Qubee creates a local Kyber/Dilithium identity. Your private key stays on-device; the shareable QR is only your public introduction bundle.",
        modifier = Modifier.fillMaxWidth(),
    )

                Spacer(Modifier.height(24.dp))

                if (s is OnboardingState.Loading) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(8.dp))
                    Text("Generating Ed25519 + Dilithium-2 keys, signing identity bundle…")
                } else {
                    Button(
                        onClick = { viewModel.createIdentity(nickname) },
                        enabled = nickname.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Create identity") }
                }

    QubeePanel {
        Text(
            "Create secure identity",
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.height(6.dp))
        QubeeMutedText("This is your cryptographic callsign. Keep it human; Qubee handles the math gremlins.")
        Spacer(Modifier.height(18.dp))

        OutlinedTextField(
            value = nickname,
            onValueChange = onNicknameChange,
            label = { Text("Display name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(18.dp))

        if (state is OnboardingState.Loading) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CircularProgressIndicator(color = QubeePalette.Cyan, modifier = Modifier.size(28.dp))
                Spacer(Modifier.width(12.dp))
                QubeeMutedText("Generating Kyber/Dilithium keys + ZK proof…")
            }
        } else {
            QubeePrimaryButton(
                text = "Create identity",
                onClick = onCreate,
                enabled = nickname.isNotBlank(),
            )
        }

        if (state is OnboardingState.Error) {
            Spacer(Modifier.height(12.dp))
            Text(
                state.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
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

    QubeeHeroMark()
    Spacer(Modifier.height(18.dp))
    QubeeStatusPill("IDENTITY ONLINE")
    Spacer(Modifier.height(14.dp))

    Text(
        "Identity ready",
        color = QubeePalette.Text,
        style = MaterialTheme.typography.headlineLarge,
        fontWeight = FontWeight.Black,
    )
    QubeeMutedText(bundle.displayName)

    Spacer(Modifier.height(22.dp))

    QubeePanel {
        Text("Public introduction bundle", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(6.dp))
        QubeeMutedText("Share this QR/link with a peer to establish contact. It does not contain your private keys.")
        Spacer(Modifier.height(16.dp))

        bitmap?.let {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .size(248.dp)
                    .clip(RoundedCornerShape(28.dp))
                    .background(QubeePalette.Text)
                    .padding(12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Image(
                    bitmap = it.asImageBitmap(),
                    contentDescription = "Your Qubee identity QR",
                    modifier = Modifier.fillMaxSize(),
                )
            }
            Spacer(Modifier.height(14.dp))
        }

        Text(
            "Fingerprint",
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Bold,
        )
        Text(
            bundle.fingerprint,
            color = QubeePalette.Cyan,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )

        if (link != null) {
            Spacer(Modifier.height(12.dp))
            Text(
                link,
                color = QubeePalette.MutedText,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(14.dp))
            QubeeSecondaryButton(
                text = "Share link",
                onClick = {
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, link)
                    }
                    context.startActivity(Intent.createChooser(intent, "Share Qubee identity"))
                },
            )
        }

        Spacer(Modifier.height(12.dp))
        QubeePrimaryButton(text = "Continue", onClick = onDone)
    }
}
