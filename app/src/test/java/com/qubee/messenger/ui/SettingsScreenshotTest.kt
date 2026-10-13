package com.qubee.messenger.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.settings.IdentityPanelBody
import com.qubee.messenger.ui.settings.NetworkPanelBody
import com.qubee.messenger.ui.settings.ResetButton
import com.qubee.messenger.ui.theme.QubeePalette
import org.junit.Rule
import org.junit.Test

/**
 * Baselines for the Settings cards: the identity card, the reaching
 * other phones card empty and connected, and the reset action in both
 * states. Each drives the stateless body without a ViewModel.
 */
class SettingsScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface(color = QubeePalette.Void) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(20.dp),
                ) { content() }
            }
        }
    }

    @Test
    fun identity_panel() {
        host {
            IdentityPanelBody(
                name = "Alex Rydén",
                fingerprint = "7c4e 19b2 0d8a 5f31 c6e9 42ab d07f 8e15",
                onMyCode = {},
                onShare = {},
            )
        }
    }

    @Test
    fun reset_enabled() {
        host { ResetButton(enabled = true, onClick = {}) }
    }

    @Test
    fun reset_disabled() {
        host { ResetButton(enabled = false, onClick = {}) }
    }

    /** Fresh install: nothing configured, node not up yet. */
    @Test
    fun network_panel_idle() {
        host {
            NetworkPanelBody(
                lanDiscoveryEnabled = false,
                onToggleLanDiscovery = {},
                bootstrapPeers = "",
                onSaveBootstrapPeers = {},
                listenAddresses = emptyList(),
                connectedPeerCount = 0,
                onCopyAddresses = {},
            )
        }
    }

    /** LAN discovery on, one bootstrap peer saved, one peer connected. */
    @Test
    fun network_panel_connected() {
        host {
            NetworkPanelBody(
                lanDiscoveryEnabled = true,
                onToggleLanDiscovery = {},
                bootstrapPeers = "/ip4/192.168.1.20/tcp/4001/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp",
                onSaveBootstrapPeers = {},
                listenAddresses = listOf(
                    "/ip4/192.168.1.5/tcp/40123/p2p/12D3KooWLRPJAEnf6wFSZnx1QhA1XgsM1mQCgTjmEU5tYgQZKRMV",
                    "/ip4/192.168.1.5/udp/40123/quic-v1/p2p/12D3KooWLRPJAEnf6wFSZnx1QhA1XgsM1mQCgTjmEU5tYgQZKRMV",
                ),
                connectedPeerCount = 1,
                onCopyAddresses = {},
            )
        }
    }
}
