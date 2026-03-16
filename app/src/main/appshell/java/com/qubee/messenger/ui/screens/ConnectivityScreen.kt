package com.qubee.messenger.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.model.ConnectivityDiagnostics
import com.qubee.messenger.model.NativeAvailability
import com.qubee.messenger.model.NativeBridgeStatus
import com.qubee.messenger.model.RelayConnectionState
import com.qubee.messenger.model.RelayStatus
import com.qubee.messenger.ui.components.QubeeChipTone
import com.qubee.messenger.ui.components.QubeePanel
import com.qubee.messenger.ui.components.QubeeSectionHeader
import com.qubee.messenger.ui.components.QubeeSignalDot
import com.qubee.messenger.ui.components.QubeeStatusChip

@Composable
fun ConnectivityScreen(
    nativeStatus: NativeBridgeStatus,
    relayStatus: RelayStatus,
    diagnostics: ConnectivityDiagnostics,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        QubeeSectionHeader(
            title = "Connectivity",
            subtitle = "Peer discovery, RTC, relay fallback, and sync status without turning the app into a submarine dashboard built by insomniacs.",
        )

        QubeePanel(title = "Live transport state") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QubeeStatusChip(
                    label = relayStatus.state.name.lowercase(),
                    tone = when (relayStatus.state) {
                        RelayConnectionState.Connected -> QubeeChipTone.Positive
                        RelayConnectionState.Error -> QubeeChipTone.Danger
                        RelayConnectionState.Authenticating,
                        RelayConnectionState.Connecting -> QubeeChipTone.Warning
                        RelayConnectionState.Disconnected -> QubeeChipTone.Neutral
                    },
                )
                QubeeStatusChip(
                    label = when (nativeStatus.availability) {
                        NativeAvailability.Ready -> "native hybrid ready"
                        NativeAvailability.FallbackMock -> "preview-only crypto"
                        NativeAvailability.Unavailable -> "native offline"
                    },
                    tone = when (nativeStatus.availability) {
                        NativeAvailability.Ready -> QubeeChipTone.Positive
                        NativeAvailability.FallbackMock -> QubeeChipTone.Danger
                        NativeAvailability.Unavailable -> QubeeChipTone.Warning
                    },
                )
            }
            Text(relayStatus.details, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(nativeStatus.details, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(diagnostics.webRtcDetails, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        QubeePanel(title = "Security posture") {
            QubeeStatusChip(
                label = if (diagnostics.secureMessagingReady) "trusted native path" else "preview-only fallback",
                tone = if (diagnostics.secureMessagingReady) QubeeChipTone.Positive else QubeeChipTone.Danger,
            )
            Text(diagnostics.securityPosture, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        QubeePanel(title = "Bootstrap and recovery") {
            ConnectivityRow("Local bootstrap", diagnostics.localBootstrapDetails)
            ConnectivityRow("RTC path", diagnostics.webRtcDetails)
            ConnectivityRow("Open peer channels", "${diagnostics.openChannelCount} channel(s) currently open.")
            ConnectivityRow("Known conversations", "${diagnostics.knownConversationCount} conversation(s) tracked in the local vault.")
            ConnectivityRow("Readiness", if (diagnostics.localBootstrapReady && diagnostics.webRtcReady) "Bootstrap and RTC paths are both reporting ready." else "One or more transport layers are still warming up or degraded.")
        }
    }
}

@Composable
private fun ConnectivityRow(label: String, description: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        QubeeSignalDot(active = true, modifier = Modifier.padding(top = 5.dp))
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurface)
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
