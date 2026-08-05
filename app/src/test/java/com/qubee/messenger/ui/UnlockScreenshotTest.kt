package com.qubee.messenger.ui

import com.qubee.messenger.ui.lock.UnlockScreen
import org.junit.Rule
import org.junit.Test

/**
 * Baselines for the biometric / device-credential lock gate: the
 * clean state and the post-failure state (a cancelled or errored
 * auth attempt leaves a reason on screen with the retry button).
 */
class UnlockScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    @Test
    fun unlock_clean() {
        paparazzi.snapshot {
            UnlockScreen(error = null, onUnlockClick = {})
        }
    }

    @Test
    fun unlock_after_failed_attempt() {
        paparazzi.snapshot {
            UnlockScreen(
                error = "Authentication cancelled. Tap Unlock to try again.",
                onUnlockClick = {},
            )
        }
    }
}
