package com.qubee.messenger.ui.invite

import android.app.Activity
import android.content.Context
import android.content.Intent
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * Thin wrapper over the embedded ZXing scanner. Use `ScanContract` from
 * a `ComponentActivity` / `Fragment`:
 *
 * ```
 * private val scan = registerForActivityResult(QrScannerActivity.contract()) { result ->
 *     result.contents?.let { handleScannedQubeeLink(it) }
 * }
 * scan.launch(QrScannerActivity.options(this))
 * ```
 */
class QrScannerActivity : CaptureActivity() {
    companion object {
        fun contract(): ScanContract = ScanContract()

        fun options(context: Context, prompt: String = "Scan a Qubee invite QR"): ScanOptions {
            return ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt(prompt)
                setBeepEnabled(true)
                setOrientationLocked(false)
                setCaptureActivity(QrScannerActivity::class.java)
            }
        }

        fun resultIntent(text: String?): Intent {
            return Intent().apply { putExtra("SCAN_RESULT", text) }
        }

        fun extractScanResult(resultCode: Int, data: Intent?): String? {
            return if (resultCode == Activity.RESULT_OK) data?.getStringExtra("SCAN_RESULT") else null
        }
    }
}
