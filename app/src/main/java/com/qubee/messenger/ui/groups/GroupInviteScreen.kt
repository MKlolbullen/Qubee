package com.qubee.messenger.ui.groups

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.R
import com.qubee.messenger.ui.invite.QrScannerActivity
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQrCard
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeSectionLabel
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTextField
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeTopBar
import com.qubee.messenger.util.QrUtils
import com.qubee.messenger.util.shareText

/**
 * New group: create one and show its invite as a code, or join one by
 * scanning or pasting an invite. Acceptance is the view model's job;
 * the screen only reports how the signed join request went.
 */
@Composable
fun GroupInviteScreen(
    viewModel: GroupInviteViewModel,
    onBack: () -> Unit,
) {
    QubeeTheme {
        val state by viewModel.state.collectAsStateWithLifecycle()
        val context = LocalContext.current
        val snackbarHost = remember { SnackbarHostState() }
        var pastedLink by rememberSaveable { mutableStateOf("") }
        var newGroupName by rememberSaveable { mutableStateOf("") }
        val scanPrompt = stringResource(R.string.group_scan_prompt)
        val shareTitle = stringResource(R.string.chat_share_invite_title)

        val scanLauncher = rememberLauncherForActivityResult(QrScannerActivity.contract()) { result ->
            result.contents?.let { scanned ->
                if (QrUtils.isInviteLink(scanned)) viewModel.decodeScannedLink(scanned)
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
            GroupInviteBody(
                state = state,
                maxMembers = viewModel.maxMembers,
                newGroupName = newGroupName,
                onNewGroupNameChange = { newGroupName = it },
                pastedLink = pastedLink,
                onPastedLinkChange = { pastedLink = it },
                onBack = onBack,
                onCreate = { viewModel.createGroupAndInvite(newGroupName.trim()) },
                onShareInvite = { state.generatedLink?.let { shareText(context, it, shareTitle) } },
                onScan = { scanLauncher.launch(QrScannerActivity.options(context, scanPrompt)) },
                onInspect = { viewModel.decodeScannedLink(pastedLink.trim()) },
                onJoin = viewModel::acceptInvite,
                onDiscard = viewModel::clearScanned,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

/** Stateless render of the New group screen, exposed for Paparazzi. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun GroupInviteBody(
    state: InviteUiState,
    maxMembers: Int,
    newGroupName: String,
    onNewGroupNameChange: (String) -> Unit,
    pastedLink: String,
    onPastedLinkChange: (String) -> Unit,
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onShareInvite: () -> Unit,
    onScan: () -> Unit,
    onInspect: () -> Unit,
    onJoin: () -> Unit,
    onDiscard: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        QubeeTopBar(title = stringResource(R.string.group_title), onBack = onBack)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 28.dp),
        ) {
            if (state.isWorking) {
                Row(
                    modifier = Modifier.padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(color = QubeePalette.Cyan, modifier = Modifier.size(22.dp))
                    Spacer(Modifier.width(12.dp))
                    QubeeMutedText(stringResource(R.string.group_working))
                }
                Spacer(Modifier.height(12.dp))
            }

            val link = state.generatedLink
            if (link == null && state.scannedInvite == null) {
                QubeePanel {
                    Text(
                        text = stringResource(R.string.group_create_title),
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Spacer(Modifier.height(4.dp))
                    QubeeMutedText(
                        text = stringResource(R.string.group_create_body, maxMembers),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(14.dp))
                    QubeeTextField(
                        value = newGroupName,
                        onValueChange = onNewGroupNameChange,
                        label = stringResource(R.string.group_name_label),
                    )
                    Spacer(Modifier.height(14.dp))
                    QubeePrimaryButton(
                        text = stringResource(R.string.group_create_button),
                        onClick = onCreate,
                        enabled = newGroupName.isNotBlank() && !state.isWorking,
                    )
                }
            }

            if (link != null) {
                val bitmap = remember(link) { QrUtils.encodeAsBitmap(link, sizePx = 540) }
                QubeeQrCard(
                    bitmap = bitmap,
                    contentDescription = stringResource(R.string.group_qr_description),
                    title = state.groupName ?: stringResource(R.string.group_invite_ready),
                    body = stringResource(R.string.group_qr_body),
                )
                Spacer(Modifier.height(12.dp))
                QubeeSecondaryButton(
                    text = stringResource(R.string.group_share_invite),
                    onClick = onShareInvite,
                    icon = Icons.Filled.Share,
                )
            }

            val invite = state.scannedInvite
            if (invite != null) {
                Spacer(Modifier.height(if (link != null) 20.dp else 0.dp))
                QubeePanel {
                    QubeeStatusPill(
                        text = stringResource(if (invite.isExpired) R.string.group_invite_expired else R.string.group_invite_checked),
                        color = if (invite.isExpired) QubeePalette.Danger else QubeePalette.Green,
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = invite.groupName,
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.headlineSmall,
                    )
                    Spacer(Modifier.height(4.dp))
                    QubeeMutedText(stringResource(R.string.group_invite_from, invite.inviterName, invite.maxMembers))
                    if (invite.isExpired) {
                        Spacer(Modifier.height(10.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.GppMaybe, contentDescription = null, tint = QubeePalette.Warning, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            QubeeMutedText(stringResource(R.string.group_invite_expired_note), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    state.acceptanceResult?.let { result ->
                        Spacer(Modifier.height(10.dp))
                        QubeeMutedText(
                            text = stringResource(if (result.networkPublished) R.string.group_accept_sent else R.string.group_accept_offline),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                    QubeePrimaryButton(
                        text = if (state.accepted) stringResource(R.string.group_joined) else stringResource(R.string.group_join_button, invite.groupName),
                        onClick = onJoin,
                        enabled = !invite.isExpired && state.scannedLink != null && !state.accepted && !state.isWorking,
                    )
                    Spacer(Modifier.height(10.dp))
                    QubeeSecondaryButton(text = stringResource(R.string.group_discard), onClick = onDiscard)
                }
            }

            if (invite == null) {
                Spacer(Modifier.height(24.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Divider(modifier = Modifier.weight(1f), color = QubeePalette.PanelAlt)
                    Spacer(Modifier.width(12.dp))
                    QubeeSectionLabel(stringResource(R.string.group_join_divider))
                    Spacer(Modifier.width(12.dp))
                    Divider(modifier = Modifier.weight(1f), color = QubeePalette.PanelAlt)
                }
                Spacer(Modifier.height(20.dp))
                QubeePanel {
                    Text(
                        text = stringResource(R.string.group_join_title),
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Spacer(Modifier.height(4.dp))
                    QubeeMutedText(stringResource(R.string.group_join_body), style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(14.dp))
                    QubeeSecondaryButton(
                        text = stringResource(R.string.group_scan),
                        onClick = onScan,
                        icon = Icons.Filled.QrCodeScanner,
                    )
                    Spacer(Modifier.height(12.dp))
                    QubeeTextField(
                        value = pastedLink,
                        onValueChange = onPastedLinkChange,
                        placeholder = stringResource(R.string.group_paste_placeholder),
                        monospace = true,
                    )
                    Spacer(Modifier.height(12.dp))
                    QubeePrimaryButton(
                        text = stringResource(R.string.group_check_link),
                        onClick = onInspect,
                        enabled = QrUtils.isInviteLink(pastedLink.trim()) && !state.isWorking,
                    )
                }
            }
        }
    }
}
