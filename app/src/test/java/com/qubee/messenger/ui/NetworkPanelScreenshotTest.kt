package com.qubee.messenger.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.android.ide.common.rendering.api.SessionParams
import com.qubee.messenger.network.NodeAddresses
import com.qubee.messenger.ui.settings.NetworkPanelBody
import com.qubee.messenger.ui.theme.QubeePalette
import org.junit.Rule
import org.junit.Test

/**
 * Baselines for the Settings network panel: the node-running state
 * (peer id + dial addresses + a saved bootstrap list) and the
 * pre-start state (no addresses, empty list, discovery off).
 */
class NetworkPanelScreenshotTest {

    // Two full dial addresses plus the bootstrap box run past a PIXEL_5
    // viewport; V_SCROLL lets the canvas grow so the whole panel lands
    // in the baseline instead of being clipped at the screen edge.
    @get:Rule
    val paparazzi = Paparazzi(
        deviceConfig = DeviceConfig.PIXEL_5,
        renderingMode = SessionParams.RenderingMode.V_SCROLL,
    )

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .background(QubeePalette.Void)
                        .padding(24.dp),
                ) { content() }
            }
        }
    }

    @Test
    fun network_node_running() {
        host {
            NetworkPanelBody(
                localDiscoveryEnabled = true,
                onLocalDiscoveryToggle = {},
                nodeAddresses = NodeAddresses(
                    peerId = "12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo",
                    listenAddrs = listOf("/ip4/192.168.1.20/tcp/41211"),
                    dialAddrs = listOf(
                        "/ip4/192.168.1.20/tcp/41211/p2p/12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo",
                        "/ip4/192.168.1.20/udp/41211/quic-v1/p2p/12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo",
                    ),
                ),
                savedBootstrapPeers = "/ip4/192.168.1.21/tcp/40001/p2p/12D3KooWBmwkafWE2fqjmhGnUdrVw6jSYxfSpfsp1mXW1v1Y5qhz",
                notice = "Saved. Dialing 1 address(es)…",
                onCopyAddresses = {},
                onRefreshAddresses = {},
                onSaveBootstrapPeers = {},
            )
        }
    }

    @Test
    fun network_node_stopped() {
        host {
            NetworkPanelBody(
                localDiscoveryEnabled = false,
                onLocalDiscoveryToggle = {},
                nodeAddresses = null,
                savedBootstrapPeers = "",
                notice = null,
                onCopyAddresses = {},
                onRefreshAddresses = {},
                onSaveBootstrapPeers = {},
            )
        }
    }
}
