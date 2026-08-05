package com.qubee.messenger.ui

import androidx.compose.runtime.Composable
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.qubee.messenger.ui.theme.QubeeTheme

/**
 * Shared Paparazzi rule factory for the screen-level baseline tests.
 *
 * PIXEL_5 is the closest built-in [DeviceConfig] to the reference
 * Galaxy S25 form factor these screens were laid out against
 * (~360x780 dp, 3x density). Keeping every screen on one device
 * config means a global theme/typography change shows up as one
 * consistent diff across all baselines rather than per-device noise.
 *
 * Record baselines:  ./gradlew :app:recordPaparazziDebug
 * Verify against:    ./gradlew :app:verifyPaparazziDebug
 *
 * The tests drive the real production composables (promoted from
 * `private` to `internal` so this same-module test source can call
 * them) with fabricated UI state — no ViewModel, no JNI, no network.
 * That keeps them deterministic and makes a snapshot diff mean "the
 * pixels changed", never "the backend behaved differently".
 */
internal fun paparazziRule(): Paparazzi = Paparazzi(deviceConfig = DeviceConfig.PIXEL_5)

/**
 * Snapshot [content] wrapped in [QubeeTheme] — the one piece of the
 * host every screen shares. Each test still supplies its own
 * screen-specific scaffold (a `QubeeScreen` background, a `Surface`,
 * etc.) inside the lambda, since those differ per screen.
 */
internal fun Paparazzi.snapshotThemed(content: @Composable () -> Unit) {
    snapshot { QubeeTheme { content() } }
}
