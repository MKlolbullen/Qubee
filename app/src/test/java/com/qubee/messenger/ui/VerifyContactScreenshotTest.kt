package com.qubee.messenger.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.qubee.messenger.ui.contacts.verification.ContactVerificationUiState
import com.qubee.messenger.ui.contacts.verification.VerifyContent
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeeTheme
import androidx.compose.foundation.background
import org.junit.Rule
import org.junit.Test

/** Baselines for the out-of-band contact verification screen: the
 * fresh compare state (fingerprint + SAS + my-fingerprint blocks) and
 * the already-verified state. */
class VerifyContactScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private val fingerprint = "AF3C 9021 7788 D4E1 5B60 2290 1C4F 8830 6612 AAB9 0071 2F5D"
    private val sas = "garden-piano-42"

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshot {
            QubeeTheme {
                Surface { androidx.compose.foundation.layout.Box(Modifier.fillMaxSize().background(QubeePalette.Void)) { content() } }
            }
        }
    }

    @Test
    fun verify_compare_state() {
        host {
            VerifyContent(
                state = ContactVerificationUiState(
                    isLoading = false,
                    contactName = "Ada Lovelace",
                    contactFingerprint = fingerprint,
                    myFingerprint = fingerprint,
                    sasCode = sas,
                    typedFingerprint = "",
                    alreadyVerified = false,
                    loadError = null,
                ),
                onTypedFingerprintChange = {},
                onConfirmFingerprint = {},
                onConfirmSas = {},
                onScanQr = {},
            )
        }
    }

    @Test
    fun verify_already_verified() {
        host {
            VerifyContent(
                state = ContactVerificationUiState(
                    isLoading = false,
                    contactName = "Ada Lovelace",
                    contactFingerprint = fingerprint,
                    myFingerprint = fingerprint,
                    sasCode = sas,
                    typedFingerprint = "",
                    alreadyVerified = true,
                    loadError = null,
                ),
                onTypedFingerprintChange = {},
                onConfirmFingerprint = {},
                onConfirmSas = {},
                onScanQr = {},
            )
        }
    }
}
