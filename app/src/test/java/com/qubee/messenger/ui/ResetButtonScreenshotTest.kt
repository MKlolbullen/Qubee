package com.qubee.messenger.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import org.junit.Rule
import org.junit.Test

/**
 * Baseline Paparazzi test. Locks in the visual of the destructive
 * "Reset identity" button + supporting copy from SettingsFragment so
 * later changes to colors / typography / button shape break this
 * test before they ship.
 *
 * Run baselines:   ./gradlew :app:recordPaparazziDebug
 * Diff against:    ./gradlew :app:verifyPaparazziDebug
 *
 * The composable is replicated inline here (instead of imported from
 * SettingsFragment.kt) because the production helper is `private`.
 * When you make the production version testable, replace this body
 * with a direct call. The point is: this test exists so the *next*
 * UI change has a snapshot to diff against.
 */
class ResetButtonScreenshotTest {

    @get:Rule
    val paparazzi = Paparazzi(
        // Galaxy S25 reports as ~360x780 dp at the default font scale
        // (1080x2340 px native, 3x density). PIXEL_5 is the closest
        // built-in DeviceConfig — same form factor.
        deviceConfig = DeviceConfig.PIXEL_5,
    )

    @Test
    fun reset_identity_section_default() {
        paparazzi.snapshot {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxWidth().padding(24.dp)) {
                    Column(verticalArrangement = Arrangement.Top) {
                        Text("Identity", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Reset deletes the local identity keystore " +
                                "(private keys and group state) and " +
                                "forces re-onboarding.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = {},
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer,
                                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                            ),
                        ) { Text("Reset identity") }
                    }
                }
            }
        }
    }
}
