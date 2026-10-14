package com.qubee.messenger.ui.connect

import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.invite.QrScannerActivity
import com.qubee.messenger.ui.settings.SettingsViewModel
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQrCard
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeSectionLabel
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeToggleRow
import com.qubee.messenger.ui.theme.QubeeTopBar
import com.qubee.messenger.util.QrUtils
import com.qubee.messenger.util.shareText
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

/**
 * "Add someone": the local identity as a code for the other phone to
 * scan, the scanner for their code, and the two ways the phones then
 * reach each other. Reuses [SettingsViewModel] for the identity bundle
 * and the Wi-Fi discovery preference so the switch here and the one in
 * Settings are the same setting.
 */
@AndroidEntryPoint
class ConnectFragment : Fragment() {

    private val viewModel: SettingsViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            QubeeTheme {
                val identity by viewModel.identity.collectAsStateWithLifecycle()
                val lanDiscovery by viewModel.lanDiscoveryEnabled.collectAsStateWithLifecycle()
                val context = LocalContext.current
                val snackbarHostState = remember { SnackbarHostState() }
                val scope = rememberCoroutineScope()
                val invalidCode = stringResource(R.string.connect_scan_invalid)
                val scanPrompt = stringResource(R.string.connect_scan_prompt)
                val scanner = rememberLauncherForActivityResult(QrScannerActivity.contract()) { result ->
                    val text = result.contents ?: return@rememberLauncherForActivityResult
                    if (QrUtils.isIdentityLink(text)) {
                        findNavController().navigate(
                            R.id.action_connect_to_add_contact,
                            Bundle().apply { putString("link", text) },
                        )
                    } else {
                        scope.launch { snackbarHostState.showSnackbar(invalidCode) }
                    }
                }
                val shareLink = identity?.shareLink

                Scaffold(
                    containerColor = QubeePalette.Void,
                    snackbarHost = { SnackbarHost(snackbarHostState) },
                ) { padding ->
                    Box(modifier = Modifier.padding(padding)) {
                        ConnectBody(
                            shareLink = shareLink,
                            lanDiscoveryEnabled = lanDiscovery,
                            onBack = { findNavController().navigateUp() },
                            onScan = { scanner.launch(QrScannerActivity.options(context, prompt = scanPrompt)) },
                            onShare = { shareLink?.let { shareIdentityLink(context, it) } },
                            onToggleLan = viewModel::setLanDiscoveryEnabled,
                            onOpenSettings = { findNavController().navigate(R.id.action_connect_to_settings) },
                        )
                    }
                }
            }
        }
    }
}

/** Stateless render of the Add someone screen, exposed for Paparazzi. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun ConnectBody(
    shareLink: String?,
    lanDiscoveryEnabled: Boolean,
    onBack: () -> Unit,
    onScan: () -> Unit,
    onShare: () -> Unit,
    onToggleLan: (Boolean) -> Unit,
    onOpenSettings: () -> Unit,
) {
    val bitmap = remember(shareLink) { shareLink?.let { QrUtils.encodeAsBitmap(it, sizePx = 540) } }
    Column(modifier = Modifier.fillMaxSize()) {
        QubeeTopBar(title = stringResource(R.string.connect_title), onBack = onBack)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 28.dp),
        ) {
            if (shareLink != null) {
                QubeeQrCard(
                    bitmap = bitmap,
                    contentDescription = stringResource(R.string.connect_qr_description),
                    title = stringResource(R.string.connect_qr_title),
                    body = stringResource(R.string.connect_qr_body),
                )
            } else {
                QubeePanel { QubeeMutedText(stringResource(R.string.connect_no_identity)) }
            }

            Spacer(Modifier.height(20.dp))
            QubeePrimaryButton(
                text = stringResource(R.string.connect_scan),
                onClick = onScan,
                icon = Icons.Filled.QrCodeScanner,
            )
            Spacer(Modifier.height(10.dp))
            QubeeSecondaryButton(
                text = stringResource(R.string.connect_share),
                onClick = onShare,
                enabled = shareLink != null,
                icon = Icons.Filled.Share,
            )

            Spacer(Modifier.height(24.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Divider(modifier = Modifier.weight(1f), color = QubeePalette.PanelAlt)
                Spacer(Modifier.width(12.dp))
                QubeeSectionLabel(stringResource(R.string.connect_divider))
                Spacer(Modifier.width(12.dp))
                Divider(modifier = Modifier.weight(1f), color = QubeePalette.PanelAlt)
            }
            Spacer(Modifier.height(20.dp))

            QubeePanel {
                QubeeToggleRow(
                    title = stringResource(R.string.connect_lan_title),
                    body = stringResource(R.string.connect_lan_body),
                    checked = lanDiscoveryEnabled,
                    onCheckedChange = onToggleLan,
                    icon = Icons.Outlined.Wifi,
                )
            }

            Spacer(Modifier.height(12.dp))
            QubeePanel {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.connect_other_title),
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.titleMedium,
                    )
                    TextButton(onClick = onOpenSettings) {
                        Text(
                            stringResource(R.string.connect_other_action),
                            color = QubeePalette.Cyan,
                            style = MaterialTheme.typography.labelLarge,
                        )
                    }
                }
                QubeeMutedText(
                    stringResource(R.string.connect_other_body),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

/** Open the system share sheet with the identity link as plain text. */
internal fun shareIdentityLink(context: Context, link: String) {
    shareText(context, link, context.getString(R.string.share_identity_title))
}
