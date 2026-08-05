package com.qubee.messenger.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.settings.AppLockPanelBody
import com.qubee.messenger.ui.theme.QubeePalette
import org.junit.Rule
import org.junit.Test

/** Baselines for the Settings screen-lock toggle panel, in both the
 * off (default) and on states. */
class AppLockPanelScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .background(QubeePalette.Void)
                        .padding(24.dp),
                ) { content() }
            }
        }
    }

    @Test
    fun app_lock_off() {
        host { AppLockPanelBody(enabled = false, onToggle = {}) }
    }

    @Test
    fun app_lock_on() {
        host { AppLockPanelBody(enabled = true, onToggle = {}) }
    }
}
