package com.qubee.messenger.util

import android.content.Context
import android.content.Intent

/** Hand plain text to the system share sheet; a missing handler is not an error worth surfacing. */
fun shareText(context: Context, text: String, chooserTitle: String) {
    val sendIntent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    val chooser = Intent.createChooser(sendIntent, chooserTitle)
    chooser.flags = chooser.flags or Intent.FLAG_ACTIVITY_NEW_TASK
    runCatching { context.startActivity(chooser) }
}
