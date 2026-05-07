package com.qubee.messenger.ui.contacts.verification

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.qubee.messenger.ui.theme.QubeeTheme
import dagger.hilt.android.AndroidEntryPoint

/**
 * Hosts the full-screen identity verification surface
 * ([VerifyContactScreen]). Launched from the Contacts long-press
 * "Verify" item with the contact's `IdentityId` (lowercase 64-char
 * hex) as an Intent extra; the screen's ViewModel resolves the
 * matching Contact row from the local address book.
 *
 * `VerificationMethod` is kept for backwards-compat with anywhere
 * that still calls [createIntent] with a method hint. Today the
 * screen surfaces *all* available paths simultaneously
 * (fingerprint compare, SAS, peer-scans-me QR), so the hint is
 * advisory; the user picks whichever ceremony works for them.
 */
@AndroidEntryPoint
class ContactVerificationActivity : ComponentActivity() {

    enum class VerificationMethod { QR_CODE, NFC, SHARED_SECRET }

    private val viewModel: ContactVerificationViewModel by viewModels()

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        val payload = result?.contents ?: return@registerForActivityResult
        // The scanned text is whatever the QR encodes — for a Qubee
        // identity QR that's the textual fingerprint. The ViewModel
        // normalises whitespace + case via the `verifyIdentityKey`
        // JNI call so a scanned blob is interchangeable with a
        // typed value.
        viewModel.onQrScanned(payload)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            QubeeTheme {
                VerifyContactScreen(
                    viewModel = viewModel,
                    onClose = { finish() },
                    onScanQr = {
                        scanLauncher.launch(
                            ScanOptions().apply {
                                setPrompt("Scan the contact's verification QR")
                                setBeepEnabled(false)
                                setOrientationLocked(false)
                            },
                        )
                    },
                )
            }
        }
    }

    companion object {
        const val EXTRA_IDENTITY_ID = "identityId"
        private const val EXTRA_METHOD = "method"

        fun createIntent(
            context: Context,
            identityId: String,
            method: VerificationMethod = VerificationMethod.QR_CODE,
        ): Intent = Intent(context, ContactVerificationActivity::class.java).apply {
            putExtra(EXTRA_IDENTITY_ID, identityId)
            putExtra(EXTRA_METHOD, method.name)
        }

        fun launch(activity: Activity, identityId: String) {
            activity.startActivity(createIntent(activity, identityId))
        }
    }
}
