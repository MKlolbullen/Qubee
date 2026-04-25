package com.qubee.messenger.util

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Helpers for rendering Qubee deep links (`qubee://identity/...`,
 * `qubee://invite/...`) as QR codes.
 *
 * Scanning is handled via the `journeyapps:zxing-android-embedded`
 * `IntentIntegrator` from the launching `Activity` / `Fragment`; see
 * [com.qubee.messenger.ui.invite.QrScannerActivity] for the wrapper.
 */
object QrUtils {

    /**
     * Render the provided string as a black-on-white square QR Bitmap of
     * the given pixel size. Returns null only on encoder failure (e.g.
     * payload too large for the chosen size).
     */
    fun encodeAsBitmap(content: String, sizePx: Int = 720): Bitmap? {
        if (content.isBlank()) return null
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        )
        return try {
            val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
            val width = matrix.width
            val height = matrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }
            bitmap
        } catch (e: Exception) {
            null
        }
    }

    /** Returns true when [text] looks like a Qubee deep link of any flavour. */
    fun isQubeeLink(text: String?): Boolean =
        !text.isNullOrBlank() && text.startsWith("qubee://")

    fun isInviteLink(text: String?): Boolean =
        !text.isNullOrBlank() && text.startsWith("qubee://invite/")

    fun isIdentityLink(text: String?): Boolean =
        !text.isNullOrBlank() && text.startsWith("qubee://identity/")
}
