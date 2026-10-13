package com.qubee.messenger.ui.settings

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.connect.shareIdentityLink
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeDangerButton
import com.qubee.messenger.ui.theme.QubeeMono
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTextField
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeToggleRow
import com.qubee.messenger.ui.theme.qubeeInitials
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class SettingsFragment : Fragment() {

    private val viewModel: SettingsViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            SettingsContent(
                viewModel = viewModel,
                onResetComplete = ::routeToOnboarding,
                onOpenConnect = { findNavController().navigate(R.id.action_settings_to_connect) },
            )
        }
    }

    /**
     * After a successful reset, pop everything off the back stack and
     * land on onboarding so the user is forced through the
     * identity-creation flow again before doing anything else.
     */
    private fun routeToOnboarding() {
        val nav = findNavController()
        nav.navigate(
            R.id.onboardingFragment,
            null,
            NavOptions.Builder()
                .setPopUpTo(nav.graph.startDestinationId, /* inclusive = */ true)
                .build(),
        )
    }
}

@Composable
private fun SettingsContent(
    viewModel: SettingsViewModel,
    onResetComplete: () -> Unit,
    onOpenConnect: () -> Unit,
) {
    QubeeTheme {
        val state by viewModel.state.collectAsStateWithLifecycle()
        var confirmOpen by remember { mutableStateOf(false) }
        val snackbarHostState = remember { SnackbarHostState() }

        LaunchedEffect(state) {
            if (state is SettingsResetState.Done) {
                onResetComplete()
                viewModel.acknowledgeReset()
            }
        }
        LaunchedEffect(viewModel) {
            viewModel.appLockNotice.collect { snackbarHostState.showSnackbar(it) }
        }

        Scaffold(
            containerColor = QubeePalette.Void,
            snackbarHost = { SnackbarHost(snackbarHostState) },
        ) { padding ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 28.dp),
                verticalArrangement = Arrangement.Top,
            ) {
                Text(
                    stringResource(R.string.title_settings),
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.headlineMedium,
                )
                Spacer(Modifier.height(16.dp))

                MyIdentityPanel(viewModel, onOpenConnect)
                Spacer(Modifier.height(14.dp))

                NetworkPanel(viewModel)
                Spacer(Modifier.height(14.dp))

                AppLockPanel(viewModel)
                Spacer(Modifier.height(14.dp))

                StartOverPanel(state = state, onReset = { confirmOpen = true })
            }
        }

        if (confirmOpen) {
            AlertDialog(
                onDismissRequest = { confirmOpen = false },
                containerColor = QubeePalette.Panel,
                titleContentColor = QubeePalette.Text,
                textContentColor = QubeePalette.MutedText,
                title = { Text(stringResource(R.string.settings_reset_confirm_title)) },
                text = { Text(stringResource(R.string.settings_reset_confirm_body)) },
                confirmButton = {
                    TextButton(
                        onClick = {
                            confirmOpen = false
                            viewModel.resetIdentity()
                        },
                    ) { Text(stringResource(R.string.settings_reset_confirm_ok), color = QubeePalette.Danger) }
                },
                dismissButton = {
                    TextButton(onClick = { confirmOpen = false }) {
                        Text(stringResource(R.string.cancel), color = QubeePalette.MutedText)
                    }
                },
            )
        }
    }
}

@Composable
private fun MyIdentityPanel(viewModel: SettingsViewModel, onOpenConnect: () -> Unit) {
    val identity by viewModel.identity.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val bundle = identity
    IdentityPanelBody(
        name = bundle?.displayName,
        fingerprint = bundle?.fingerprint,
        onMyCode = onOpenConnect,
        onShare = { bundle?.shareLink?.let { shareIdentityLink(context, it) } },
        canShare = bundle?.shareLink != null,
    )
}

/** Stateless identity card, exposed for Paparazzi. A null name means no identity exists yet. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun IdentityPanelBody(
    name: String?,
    fingerprint: String?,
    onMyCode: () -> Unit,
    onShare: () -> Unit,
    canShare: Boolean = true,
) {
    QubeePanel {
        if (name == null) {
            Text(
                stringResource(R.string.settings_no_identity),
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(4.dp))
            QubeeMutedText(stringResource(R.string.connect_no_identity), style = MaterialTheme.typography.bodySmall)
            return@QubeePanel
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            QubeeAvatar(
                initials = name.qubeeInitials(),
                size = 52.dp,
                color = QubeePalette.Void,
                background = QubeePalette.Cyan,
            )
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    name.ifBlank { "Anonymous" },
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    fingerprint.orEmpty().ifBlank { "Not available" },
                    color = QubeePalette.MutedText,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = QubeeMono,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Spacer(Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            IdentityActionButton(
                text = stringResource(R.string.settings_my_code),
                icon = Icons.Filled.QrCode,
                primary = true,
                onClick = onMyCode,
                modifier = Modifier.weight(1f),
            )
            IdentityActionButton(
                text = stringResource(R.string.settings_share_link),
                icon = Icons.Filled.Share,
                primary = false,
                onClick = onShare,
                modifier = Modifier.weight(1f),
                enabled = canShare,
            )
        }
    }
}

@Composable
private fun IdentityActionButton(
    text: String,
    icon: ImageVector,
    primary: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.height(44.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = if (primary) QubeePalette.Cyan else QubeePalette.PanelAlt,
            contentColor = if (primary) QubeePalette.Void else QubeePalette.Text,
            disabledContainerColor = QubeePalette.Panel,
            disabledContentColor = QubeePalette.MutedText,
        ),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp),
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.labelLarge)
    }
}

/**
 * Screen-lock card. Split into a stateless [AppLockPanelBody] so the
 * visual can be snapshot-tested without a ViewModel.
 */
@Composable
private fun AppLockPanel(viewModel: SettingsViewModel) {
    val enabled by viewModel.appLockEnabled.collectAsStateWithLifecycle()
    AppLockPanelBody(enabled = enabled, onToggle = viewModel::setAppLockEnabled)
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun AppLockPanelBody(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    QubeePanel {
        QubeeToggleRow(
            title = stringResource(R.string.settings_unlock_title),
            body = stringResource(R.string.settings_unlock_body),
            checked = enabled,
            onCheckedChange = onToggle,
            icon = Icons.Outlined.Lock,
        )
    }
}

/**
 * Peer discovery controls. Split into a stateless [NetworkPanelBody]
 * so the visual can be snapshot-tested without a ViewModel.
 */
@Composable
private fun NetworkPanel(viewModel: SettingsViewModel) {
    val lanDiscovery by viewModel.lanDiscoveryEnabled.collectAsStateWithLifecycle()
    val bootstrapPeers by viewModel.bootstrapPeers.collectAsStateWithLifecycle()
    val addresses by viewModel.listenAddresses.collectAsStateWithLifecycle()
    val peers by viewModel.connectedPeers.collectAsStateWithLifecycle()
    val clipboard = LocalClipboardManager.current
    NetworkPanelBody(
        lanDiscoveryEnabled = lanDiscovery,
        onToggleLanDiscovery = viewModel::setLanDiscoveryEnabled,
        bootstrapPeers = bootstrapPeers,
        onSaveBootstrapPeers = viewModel::saveBootstrapPeers,
        listenAddresses = addresses,
        connectedPeerCount = peers.size,
        onCopyAddresses = {
            clipboard.setText(AnnotatedString(addresses.joinToString("\n")))
        },
    )
}

/** Stateless render of [NetworkPanel]'s content, exposed for Paparazzi snapshot tests. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun NetworkPanelBody(
    lanDiscoveryEnabled: Boolean,
    onToggleLanDiscovery: (Boolean) -> Unit,
    bootstrapPeers: String,
    onSaveBootstrapPeers: (String) -> Unit,
    listenAddresses: List<String>,
    connectedPeerCount: Int,
    onCopyAddresses: () -> Unit,
) {
    var draft by remember(bootstrapPeers) { mutableStateOf(bootstrapPeers) }
    QubeePanel {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.settings_network_title),
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
            )
            QubeeStatusPill(
                text = stringResource(R.string.settings_connected_count, connectedPeerCount),
                color = if (connectedPeerCount > 0) QubeePalette.Green else QubeePalette.MutedText,
                dot = true,
            )
        }

        Spacer(Modifier.height(14.dp))
        QubeeToggleRow(
            title = stringResource(R.string.connect_lan_title),
            body = stringResource(R.string.settings_lan_body),
            checked = lanDiscoveryEnabled,
            onCheckedChange = onToggleLanDiscovery,
        )

        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(R.string.settings_address_title),
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.labelMedium,
        )
        Spacer(Modifier.height(8.dp))
        if (listenAddresses.isEmpty()) {
            QubeeMutedText(stringResource(R.string.settings_address_none), style = MaterialTheme.typography.bodySmall)
        } else {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = QubeePalette.Void,
                border = BorderStroke(1.dp, QubeePalette.PanelAlt),
            ) {
                Row(
                    modifier = Modifier.padding(start = 12.dp, top = 6.dp, bottom = 6.dp, end = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        listenAddresses.forEach { address ->
                            Text(
                                address,
                                color = QubeePalette.Text,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = QubeeMono,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                    IconButton(onClick = onCopyAddresses, modifier = Modifier.size(44.dp)) {
                        Icon(
                            Icons.Filled.ContentCopy,
                            contentDescription = stringResource(R.string.settings_copy_address),
                            tint = QubeePalette.Cyan,
                        )
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(R.string.settings_peer_address_label),
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.labelMedium,
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.Top) {
            QubeeTextField(
                value = draft,
                onValueChange = { draft = it },
                placeholder = stringResource(R.string.settings_peer_address_placeholder),
                singleLine = false,
                monospace = true,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = { onSaveBootstrapPeers(draft) },
                enabled = draft.trim() != bootstrapPeers.trim(),
                modifier = Modifier.height(56.dp),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = QubeePalette.PanelAlt,
                    contentColor = QubeePalette.Text,
                    disabledContainerColor = QubeePalette.Panel,
                    disabledContentColor = QubeePalette.MutedText,
                ),
            ) { Text(stringResource(R.string.settings_connect), style = MaterialTheme.typography.labelLarge) }
        }
        Spacer(Modifier.height(8.dp))
        QubeeMutedText(stringResource(R.string.settings_retry_note), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun StartOverPanel(state: SettingsResetState, onReset: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = QubeePalette.Panel,
        border = BorderStroke(1.dp, QubeePalette.Danger.copy(alpha = 0.4f)),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                stringResource(R.string.settings_start_over_title),
                color = QubeePalette.Danger,
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(6.dp))
            QubeeMutedText(stringResource(R.string.settings_start_over_body), style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(14.dp))
            when (state) {
                SettingsResetState.Working -> CircularProgressIndicator(color = QubeePalette.Cyan)
                is SettingsResetState.Error -> {
                    Text(
                        state.message,
                        color = QubeePalette.Danger,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(12.dp))
                    ResetButton(enabled = true, onClick = onReset)
                }
                else -> ResetButton(enabled = state !is SettingsResetState.Done, onClick = onReset)
            }
        }
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun ResetButton(enabled: Boolean, onClick: () -> Unit) {
    QubeeDangerButton(
        text = stringResource(R.string.settings_reset_button),
        onClick = onClick,
        enabled = enabled,
    )
}
