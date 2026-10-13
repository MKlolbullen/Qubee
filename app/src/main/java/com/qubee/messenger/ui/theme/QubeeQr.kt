package com.qubee.messenger.ui.theme

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.qubee.messenger.R

/** A QR code on the one light surface in the app, so any camera reads it. */
@Composable
fun QubeeQrCard(
    bitmap: Bitmap?,
    contentDescription: String,
    modifier: Modifier = Modifier,
    title: String? = null,
    body: String? = null,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = QubeePalette.Text,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (bitmap != null) {
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = contentDescription,
                    modifier = Modifier.size(200.dp),
                )
            } else {
                Box(modifier = Modifier.size(200.dp), contentAlignment = Alignment.Center) {
                    Text(
                        text = stringResource(R.string.qr_unavailable),
                        color = Color(0xFF43596B),
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            if (title != null) {
                Spacer(Modifier.height(12.dp))
                Text(
                    text = title,
                    color = QubeePalette.Void,
                    style = MaterialTheme.typography.titleMedium,
                    textAlign = TextAlign.Center,
                )
            }
            if (body != null) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = body,
                    color = Color(0xFF43596B),
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
