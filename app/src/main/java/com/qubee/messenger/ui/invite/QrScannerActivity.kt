package com.qubee.messenger.ui.invite

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.qubee.messenger.R

/**
 * The embedded ZXing scanner in Qubee's clothes. Every scan in the app
 * goes through here so the camera screen looks the same whether it is
 * reading a contact's code, a group invite or a confirmation code.
 *
 * ```
 * private val scan = registerForActivityResult(QrScannerActivity.contract()) { result ->
 *     result.contents?.let { handleScannedQubeeLink(it) }
 * }
 * scan.launch(QrScannerActivity.options(this))
 * ```
 */
class QrScannerActivity : CaptureActivity() {

    override fun initializeContent(): DecoratedBarcodeView {
        setContentView(R.layout.activity_qr_scanner)
        return findViewById(R.id.zxing_barcode_scanner)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        findViewById<View>(R.id.scanner_back).setOnClickListener { finish() }
    }

    companion object {
        fun contract(): ScanContract = ScanContract()

        fun options(context: Context, prompt: String = context.getString(R.string.scan_prompt_default)): ScanOptions {
            return ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt(prompt)
                setBeepEnabled(false)
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
