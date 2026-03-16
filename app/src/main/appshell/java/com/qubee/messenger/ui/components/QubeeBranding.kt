package com.qubee.messenger.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.theme.QubeeGlow
import com.qubee.messenger.ui.theme.QubeeOutline
import com.qubee.messenger.ui.theme.QubeePrimary
import com.qubee.messenger.ui.theme.QubeeSecondary
import com.qubee.messenger.ui.theme.QubeeSurfaceDark
import com.qubee.messenger.ui.theme.QubeeTertiary

@Composable
fun QubeeBrandGlyph(
    modifier: Modifier = Modifier,
    size: Dp = 52.dp,
) {
    Box(
        modifier = modifier
            .size(size)
            .border(width = 1.dp, color = QubeeOutline, shape = RoundedCornerShape(18.dp))
            .background(QubeeSurfaceDark.copy(alpha = 0.76f), RoundedCornerShape(18.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
        ) {
            val lineColor = QubeePrimary
            val nodeColor = QubeeSecondary
            val glowColor = QubeeGlow
            val stroke = size.minDimension * 0.028f
            val nodeRadius = size.minDimension * 0.035f
            val depth = size.minDimension * 0.16f
            val margin = size.minDimension * 0.18f

            val frontLeft = margin
            val frontTop = margin + depth
            val frontRight = size.width - margin - depth
            val frontBottom = size.height - margin

            val backLeft = margin + depth
            val backTop = margin
            val backRight = size.width - margin
            val backBottom = size.height - margin - depth

            // Glow
            drawCircle(
                color = glowColor,
                radius = size.minDimension * 0.36f,
                center = center,
            )

            fun line(start: Offset, end: Offset) {
                drawLine(color = lineColor, start = start, end = end, strokeWidth = stroke, cap = StrokeCap.Round)
            }
            fun node(x: Float, y: Float) {
                drawCircle(color = nodeColor, radius = nodeRadius, center = Offset(x, y))
            }

            // Front face
            line(Offset(frontLeft, frontTop), Offset(frontRight, frontTop))
            line(Offset(frontRight, frontTop), Offset(frontRight, frontBottom))
            line(Offset(frontRight, frontBottom), Offset(frontLeft, frontBottom))
            line(Offset(frontLeft, frontBottom), Offset(frontLeft, frontTop))

            // Back face
            line(Offset(backLeft, backTop), Offset(backRight, backTop))
            line(Offset(backRight, backTop), Offset(backRight, backBottom))
            line(Offset(backRight, backBottom), Offset(backLeft, backBottom))
            line(Offset(backLeft, backBottom), Offset(backLeft, backTop))

            // Connectors
            line(Offset(frontLeft, frontTop), Offset(backLeft, backTop))
            line(Offset(frontRight, frontTop), Offset(backRight, backTop))
            line(Offset(frontRight, frontBottom), Offset(backRight, backBottom))
            line(Offset(frontLeft, frontBottom), Offset(backLeft, backBottom))

            // Internal guide lines
            line(Offset((frontLeft + frontRight) / 2f, frontTop), Offset((backLeft + backRight) / 2f, backTop))
            line(Offset(frontLeft, (frontTop + frontBottom) / 2f), Offset(backLeft, (backTop + backBottom) / 2f))
            line(Offset(frontRight, (frontTop + frontBottom) / 2f), Offset(backRight, (backTop + backBottom) / 2f))

            // Vertex nodes (matching the green branding image)
            node(frontLeft, frontTop); node(frontRight, frontTop)
            node(frontRight, frontBottom); node(frontLeft, frontBottom)
            node(backLeft, backTop); node(backRight, backTop)
            node(backRight, backBottom); node(backLeft, backBottom)
            // Midpoint nodes on back face
            node((backLeft + backRight) / 2f, backTop)
            node((backLeft + backRight) / 2f, backBottom)
            node(backLeft, (backTop + backBottom) / 2f)
            node(backRight, (backTop + backBottom) / 2f)
        }

        Text(
            text = "QB",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            color = QubeeTertiary,
        )
    }
}

@Composable
fun QubeeBrandLockup(
    modifier: Modifier = Modifier,
    title: String = "QUBEE",
    subtitle: String? = "Post-Quantum Secure Messaging",
    glyphSize: Dp = 56.dp,
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QubeeBrandGlyph(size = glyphSize)
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
