package com.qubee.messenger.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.qubee.messenger.ui.contacts.verification.ContactVerificationUiState
import com.qubee.messenger.ui.contacts.verification.VerifyContent
import com.qubee.messenger.ui.theme.QubeePalette
import org.junit.Rule
import org.junit.Test

/** Baselines for the confirm-a-contact screen: the fresh compare state
 * (short code cards, fingerprint, scan, my code) and the already
 * confirmed state. */
class VerifyContactScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private val fingerprint = "AF3C 9021 7788 D4E1 5B60 2290 1C4F 8830 6612 AAB9 0071 2F5D"
    private val sas = "4821 0937"

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            Surface(color = QubeePalette.Void, modifier = Modifier.fillMaxSize()) { content() }
        }
    }

    @Test
    fun verify_compare_state() {
        host {
            VerifyContent(
                state = ContactVerificationUiState(
                    isLoading = false,
                    contactName = "Mira Ekholm",
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
                    contactName = "Mira Ekholm",
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
