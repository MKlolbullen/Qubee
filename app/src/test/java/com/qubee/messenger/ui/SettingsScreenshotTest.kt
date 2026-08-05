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
import com.qubee.messenger.ui.settings.ResetButton
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import androidx.compose.foundation.background
import org.junit.Rule
import org.junit.Test

/**
 * Baseline for the Settings destructive-action section, driving the
 * real production [ResetButton] (replaces the earlier inline-replica
 * test) in both its enabled and disabled states so a change to the
 * danger colours / disabled treatment breaks here before shipping.
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
}
