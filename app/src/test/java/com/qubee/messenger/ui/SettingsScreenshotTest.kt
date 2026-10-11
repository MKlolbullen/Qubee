package com.qubee.messenger.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.settings.NetworkPanelBody
import com.qubee.messenger.ui.settings.ResetButton
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import androidx.compose.foundation.background
import org.junit.Rule
import org.junit.Test

/**
 * Baselines for the Settings destructive-action section, driving the
 * real production [ResetButton] (replaces the earlier inline-replica
 * test) in both its enabled and disabled states so a change to the
 * danger colours / disabled treatment breaks here before shipping,
 * and for the peer-discovery panel ([NetworkPanelBody]) empty and
 * with addresses, a saved bootstrap peer and a connected peer.
 */
class SettingsScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .background(QubeePalette.Void)
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Top,
                ) {
                    Text("Danger zone", color = QubeePalette.Text)
                    Spacer(Modifier.height(6.dp))
                    QubeeMutedText(
                        "Destroys the local identity keystore (private keys and " +
                            "group state) and forces re-onboarding. This cannot be undone.",
                    )
                    Spacer(Modifier.height(14.dp))
                    content()
                }
            }
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

    private fun networkHost(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface(color = QubeePalette.Void) {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                ) { content() }
            }
        }
    }

    /** Fresh install: nothing configured, node not up yet. */
    @Test
    fun network_panel_idle() {
        networkHost {
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
        networkHost {
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
