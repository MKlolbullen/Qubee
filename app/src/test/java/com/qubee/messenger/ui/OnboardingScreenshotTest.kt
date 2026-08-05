package com.qubee.messenger.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.onboarding.IdentityBootstrapView
import com.qubee.messenger.ui.onboarding.OnboardingState
import com.qubee.messenger.ui.theme.QubeeScreen
import org.junit.Rule
import org.junit.Test

/**
 * Baselines for the onboarding identity-bootstrap screen — the very
 * first surface a new user sees, and the returning-user landing when
 * no identity exists yet. Locks the hero mark, callsign field, and
 * primary/error states.
 */
class OnboardingScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @androidx.compose.runtime.Composable () -> Unit) {
        paparazzi.snapshotThemed {
            QubeeScreen {
                Column(Modifier.fillMaxSize().padding(horizontal = 22.dp, vertical = 28.dp)) {
                    content()
                }
            }
        }
    }

    @Test
    fun bootstrap_idle_empty_name() {
        host {
            IdentityBootstrapView(
                state = OnboardingState.Idle,
                nickname = "",
                onNicknameChange = {},
                onCreate = {},
            )
        }
    }

    @Test
    fun bootstrap_name_entered_ready() {
        host {
            IdentityBootstrapView(
                state = OnboardingState.Idle,
                nickname = "moss",
                onNicknameChange = {},
                onCreate = {},
            )
        }
    }

    @Test
    fun bootstrap_generating_keys() {
        host {
            IdentityBootstrapView(
                state = OnboardingState.Loading,
                nickname = "moss",
                onNicknameChange = {},
                onCreate = {},
            )
        }
    }

    @Test
    fun bootstrap_error() {
        host {
            IdentityBootstrapView(
                state = OnboardingState.Error("Keystore is locked — unlock the device and retry."),
                nickname = "moss",
                onNicknameChange = {},
                onCreate = {},
            )
        }
    }
}
