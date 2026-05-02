package com.qubee.messenger.ui.groups

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import com.qubee.messenger.ui.invite.QrScannerActivity
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.util.QrUtils

/**
 * Group invite screen.
 *
 * - Create a local group and render a `qubee://invite/...` deep link as QR.
 * - Scan or paste an inbound invite and inspect the signed envelope before join.
 * - Network acceptance is delegated through [onAcceptInvite] to keep UI pure.
 */
@Composable
fun GroupInviteScreen(
    viewModel: GroupInviteViewModel,
    onAcceptInvite: (link: String) -> Unit,
) {
    QubeeTheme {
        val state by viewModel.state.collectAsState()
        val context = LocalContext.current
        val snackbarHost = remember { SnackbarHostState() }
        var pastedLink by remember { mutableStateOf("") }
        var newGroupName by remember { mutableStateOf("") }

        val scanLauncher = rememberLauncherForActivityResult(QrScannerActivity.contract()) { result ->
            result.contents?.let { scanned ->
                if (QrUtils.isInviteLink(scanned)) {
                    viewModel.decodeScannedLink(scanned)
                }
            }
        }

        LaunchedEffect(state.error) {
            val msg = state.error ?: return@LaunchedEffect
            snackbarHost.showSnackbar(msg)
            viewModel.consumeError()
        }

        Scaffold(
            containerColor = QubeePalette.Void,
            snackbarHost = { SnackbarHost(snackbarHost) },
        ) { padding ->
            QubeeScreen(
                modifier = Modifier.padding(padding),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(20.dp)
                        .verticalScroll(rememberScrollState()),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    QubeeStatusPill("GROUP HANDSHAKE")
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "Invite without leaking the hive.",
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Black,
                    )
                    Spacer(Modifier.height(6.dp))
                    QubeeMutedText(
                        "Create a local group invite, scan a peer's code, or paste a signed deep link. Max ${viewModel.maxMembers} members including creator.",
                        modifier = Modifier.fillMaxWidth(),
                    )

                    Spacer(Modifier.height(22.dp))

                    if (state.isWorking) {
                        QubeePanel {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(color = QubeePalette.Cyan, modifier = Modifier.size(28.dp))
                                Spacer(Modifier.width(12.dp))
                                QubeeMutedText("Signing invite envelope…")
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                    }

                    if (state.generatedLink == null && state.scannedInvite == null) {
                        QubeePanel {
                            Text("Create new group", style = MaterialTheme.typography.titleLarge)
                            Spacer(Modifier.height(6.dp))
                            QubeeMutedText("Mint a fresh invite QR for a peer sitting next to you. Old-school social ritual, post-quantum bones.")
                            Spacer(Modifier.height(16.dp))
                            OutlinedTextField(
                                value = newGroupName,
                                onValueChange = { newGroupName = it },
                                label = { Text("Group name") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Spacer(Modifier.height(14.dp))
                            QubeePrimaryButton(
                                text = "Create group + invite",
                                onClick = { viewModel.createGroupAndInvite(newGroupName.trim()) },
                                enabled = newGroupName.isNotBlank() && !state.isWorking,
                            )
                        }
                        Spacer(Modifier.height(16.dp))
                    }

                    state.generatedLink?.let { link ->
                        val bitmap = remember(link) { QrUtils.encodeAsBitmap(link) }
                        QubeePanel {
                            Text(
                                state.groupName ?: "Invite ready",
                                style = MaterialTheme.typography.titleLarge,
                            )
                            Spacer(Modifier.height(6.dp))
                            QubeeMutedText("Show this QR to the peer you want inside the group. Screenshotting invites is convenient. Also cursed. Prefer live exchange.")
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
                                        contentDescription = "Group invite QR code",
                                        modifier = Modifier.fillMaxSize(),
                                    )
                                }
                            }
                            Spacer(Modifier.height(12.dp))
                            Text(
                                link,
                                color = QubeePalette.MutedText,
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 3,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        Spacer(Modifier.height(16.dp))
                    }

                    QubeePanel {
                        Text("Join existing group", style = MaterialTheme.typography.titleLarge)
                        Spacer(Modifier.height(6.dp))
                        QubeeMutedText("Scan a QR or paste a `qubee://invite/...` link. The app inspects the envelope before enabling join.")
                        Spacer(Modifier.height(16.dp))

                        QubeeSecondaryButton(
                            text = "Scan invite QR",
                            onClick = { scanLauncher.launch(QrScannerActivity.options(context)) },
                        )
                        Spacer(Modifier.height(12.dp))
                        OutlinedTextField(
                            value = pastedLink,
                            onValueChange = { pastedLink = it },
                            label = { Text("Paste qubee://invite/...") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(12.dp))
                        QubeePrimaryButton(
                            text = "Inspect link",
                            onClick = { viewModel.decodeScannedLink(pastedLink.trim()) },
                            enabled = QrUtils.isInviteLink(pastedLink.trim()) && !state.isWorking,
                        )
                    }

                    state.scannedInvite?.let { invite ->
                        Spacer(Modifier.height(16.dp))
                        QubeePanel {
                            QubeeStatusPill(if (invite.isExpired) "EXPIRED" else "INVITE VERIFIED")
                            Spacer(Modifier.height(12.dp))
                            Text(
                                invite.groupName,
                                style = MaterialTheme.typography.titleLarge,
                            )
                            Spacer(Modifier.height(4.dp))
                            QubeeMutedText("Invitation from ${invite.inviterName}")
                            QubeeMutedText("Members allowed: ${invite.maxMembers}")
                            if (invite.isExpired) {
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "This invite has expired.",
                                    color = MaterialTheme.colorScheme.error,
                                    style = MaterialTheme.typography.bodyMedium,
                                )
                            }
                            state.acceptanceResult?.let { result ->
                                Spacer(Modifier.height(10.dp))
                                val msg = if (result.networkPublished) {
                                    "Saved. A signed handshake was sent; the inviter's device will enrol you when it sees it."
                                } else {
                                    "Saved locally. Network publish failed; reopen the chat while connected to retry."
                                }
                                QubeeMutedText(msg)
                            }
                            Spacer(Modifier.height(14.dp))
                            QubeePrimaryButton(
                                text = if (state.accepted) "Saved" else "Join ${invite.groupName}",
                                onClick = {
                                    viewModel.acceptInvite()
                                    state.scannedLink?.let(onAcceptInvite)
                                },
                                enabled = !invite.isExpired && state.scannedLink != null && !state.accepted,
                            )
                            Spacer(Modifier.height(10.dp))
                            QubeeSecondaryButton(
                                text = "Discard",
                                onClick = { viewModel.clearScanned() },
                            )
                        }
                    }
                }
            }
        }
    }
}
