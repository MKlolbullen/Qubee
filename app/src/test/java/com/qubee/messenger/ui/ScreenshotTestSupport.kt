package com.qubee.messenger.ui

import androidx.compose.runtime.Composable
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.android.resources.Density
import com.android.resources.ScreenRatio
import com.android.resources.ScreenSize
import com.qubee.messenger.ui.theme.QubeeTheme

/**
 * The reference phone: a Galaxy S25 Ultra, 6.9" 3120x1440 at 498 ppi.
 * Android runs it at 560 dpi (3.5x), so the screens lay out at
 * 411x891 dp, which is what these baselines render. Keeping every
 * screen on one device config means a global theme/typography change
 * shows up as one consistent diff across all baselines rather than
 * per-device noise.
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
internal val GALAXY_S25_ULTRA: DeviceConfig = DeviceConfig.PIXEL_5.copy(
    screenHeight = 3120,
    screenWidth = 1440,
    xdpi = 498,
    ydpi = 498,
    density = Density.DPI_560,
    ratio = ScreenRatio.LONG,
    size = ScreenSize.NORMAL,
    released = "February 7, 2025",
)

internal fun paparazziRule(): Paparazzi = Paparazzi(deviceConfig = GALAXY_S25_ULTRA)

/**
 * Snapshot [content] wrapped in [QubeeTheme] — the one piece of the
 * host every screen shares. Each test still supplies its own
 * screen-specific scaffold (a `QubeeScreen` background, a `Surface`,
 * etc.) inside the lambda, since those differ per screen.
 */
internal fun Paparazzi.snapshotThemed(content: @Composable () -> Unit) {
    snapshot { QubeeTheme { content() } }
}
