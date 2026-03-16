package com.qubee.messenger.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.ui.theme.*

@Composable
fun StatusChip(
    label: String,
    ok: Boolean,
    modifier: Modifier = Modifier,
) {
    val color = if (ok) QubeeSecondary else QubeeDanger
    val bg = if (ok) QubeeGlow else QubeeDanger.copy(alpha = 0.1f)
    val border = if (ok) QubeePrimary.copy(alpha = 0.2f) else QubeeDanger.copy(alpha = 0.2f)

    Row(
        modifier = modifier
            .background(bg, RoundedCornerShape(20.dp))
            .border(1.dp, border, RoundedCornerShape(20.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .background(if (ok) QubeePrimary else QubeeDanger, CircleShape),
        )
        Text(
            text = label,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = color,
        )
    }
}
