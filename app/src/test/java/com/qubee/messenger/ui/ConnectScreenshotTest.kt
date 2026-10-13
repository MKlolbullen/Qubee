package com.qubee.messenger.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.qubee.messenger.ui.connect.ConnectBody
import com.qubee.messenger.ui.theme.QubeePalette
import org.junit.Rule
import org.junit.Test

/** Baselines for the Add someone screen: with an identity to show as a
 * code, and before onboarding has produced one. */
class ConnectScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface(color = QubeePalette.Void, modifier = Modifier.fillMaxSize()) { content() }
        }
    }

    @Test
    fun connect_with_identity() {
        host {
            ConnectBody(
                shareLink = "qubee://identity/eyJ1c2VyX2lkIjoiZGVtbyIsImRpc3BsYXlfbmFtZSI6Ik1pcmEifQ",
                lanDiscoveryEnabled = false,
                onBack = {},
                onScan = {},
                onShare = {},
                onToggleLan = {},
                onOpenSettings = {},
            )
        }
    }

    @Test
    fun connect_without_identity() {
        host {
            ConnectBody(
                shareLink = null,
                lanDiscoveryEnabled = true,
                onBack = {},
                onScan = {},
                onShare = {},
                onToggleLan = {},
                onOpenSettings = {},
            )
        }
    }
}
