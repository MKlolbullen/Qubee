package com.qubee.messenger.ui.groups

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import com.qubee.messenger.ui.invite.QrScannerActivity
import com.qubee.messenger.util.QrUtils

/**
 * Group invite screen.
 *
 * - Top half: render the most recent `qubee://invite/...` deep link as a
 *   QR code so a peer can scan it on the spot.
 * - Bottom half: scan an inbound QR or paste an invite link to inspect &
 *   accept it.
 *
 * The actual "join the group" call is delegated to [onAcceptInvite] so
 * this composable stays decoupled from the network/repository layer.
 */
@Composable
fun GroupInviteScreen(
    viewModel: GroupInviteViewModel,
    onAcceptInvite: (link: String) -> Unit,
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var pastedLink by remember { mutableStateOf("") }

    val scanLauncher = rememberLauncherForActivityResult(QrScannerActivity.contract()) { result ->
        result.contents?.let { scanned ->
            if (QrUtils.isInviteLink(scanned)) {
                viewModel.decodeScannedLink(scanned)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "Group invite",
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            "Up to ${viewModel.maxMembers} members per group (creator included).",
            style = MaterialTheme.typography.bodySmall,
        )

        Spacer(Modifier.height(16.dp))

        if (state.isWorking) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
        }

        state.generatedLink?.let { link ->
            val bitmap = remember(link) { QrUtils.encodeAsBitmap(link) }
            Text(
                state.groupName ?: "Invite",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(8.dp))
            bitmap?.let {
                Image(
                    bitmap = it.asImageBitmap(),
                    contentDescription = "Group invite QR code",
                    modifier = Modifier.size(240.dp),
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(
                link,
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(16.dp))
        }

        OutlinedButton(
            onClick = { scanLauncher.launch(QrScannerActivity.options(context)) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Scan invite QR") }

        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = pastedLink,
            onValueChange = { pastedLink = it },
            label = { Text("Or paste qubee://invite/...") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { viewModel.decodeScannedLink(pastedLink.trim()) },
            enabled = QrUtils.isInviteLink(pastedLink.trim()) && !state.isWorking,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Inspect link") }

        state.scannedInvite?.let { invite ->
            Spacer(Modifier.height(16.dp))
            Text(
                "Invitation from ${invite.inviterName}",
                style = MaterialTheme.typography.titleMedium,
            )
            Text("Group: ${invite.groupName}")
            Text("Members allowed: ${invite.maxMembers}")
            if (invite.isExpired) {
                Text(
                    "This invite has expired.",
                    color = MaterialTheme.colorScheme.error,
                )
            }
            state.acceptanceResult?.let { result ->
                val msg = if (result.networkPublished) {
                    "Saved. A signed handshake was sent — the inviter's " +
                        "device will enrol you as soon as it sees it on " +
                        "the network."
                } else {
                    "Saved locally. Couldn't reach the network yet — open " +
                        "the chat once you're connected to retry the " +
                        "handshake."
                }
                Text(msg, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    viewModel.acceptInvite()
                    state.scannedLink?.let(onAcceptInvite)
                },
                enabled = !invite.isExpired && state.scannedLink != null && !state.accepted,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (state.accepted) "Saved" else "Join ${invite.groupName}") }
            OutlinedButton(
                onClick = { viewModel.clearScanned() },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Discard") }
        }

        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
    }
}
