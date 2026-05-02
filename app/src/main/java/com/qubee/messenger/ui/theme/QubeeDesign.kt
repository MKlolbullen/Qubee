package com.qubee.messenger.ui.theme

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

object QubeePalette {
    val Void = Color(0xFF040C16)
    val Void2 = Color(0xFF07111F)
    val Panel = Color(0xE60A1726)
    val PanelAlt = Color(0xF0102234)
    val Cyan = Color(0xFF12EAD8)
    val Blue = Color(0xFF00A7FF)
    val Green = Color(0xFF8CFF72)
    val Text = Color(0xFFEAFBFF)
    val MutedText = Color(0xFFA3BDCA)
    val Danger = Color(0xFFFF5C7A)
    val Warning = Color(0xFFFFCF5C)
}

private val QubeeColorScheme = darkColorScheme(
    primary = QubeePalette.Cyan,
    onPrimary = QubeePalette.Void,
    primaryContainer = QubeePalette.PanelAlt,
    onPrimaryContainer = QubeePalette.Text,
    secondary = QubeePalette.Green,
    onSecondary = QubeePalette.Void,
    background = QubeePalette.Void,
    onBackground = QubeePalette.Text,
    surface = QubeePalette.Panel,
    onSurface = QubeePalette.Text,
    surfaceVariant = QubeePalette.PanelAlt,
    onSurfaceVariant = QubeePalette.MutedText,
    error = QubeePalette.Danger,
    errorContainer = Color(0xFF32101A),
    onErrorContainer = Color(0xFFFFD7DF),
)

private val QubeeTypography = Typography(
    headlineLarge = TextStyle(
        fontWeight = FontWeight.Black,
        fontSize = 36.sp,
        lineHeight = 40.sp,
        letterSpacing = (-0.6).sp,
    ),
    headlineMedium = TextStyle(
        fontWeight = FontWeight.ExtraBold,
        fontSize = 28.sp,
        lineHeight = 34.sp,
        letterSpacing = (-0.35).sp,
    ),
    headlineSmall = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
    ),
    titleLarge = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 22.sp,
    ),
    bodyLarge = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 21.sp,
    ),
    bodySmall = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 18.sp,
    ),
    labelLarge = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
)

val QubeeQuantumBrush = Brush.linearGradient(
    colors = listOf(QubeePalette.Green, QubeePalette.Cyan, QubeePalette.Blue),
)

val QubeePanelBorder = Brush.linearGradient(
    colors = listOf(
        QubeePalette.Cyan.copy(alpha = 0.70f),
        QubeePalette.Blue.copy(alpha = 0.30f),
        QubeePalette.Green.copy(alpha = 0.35f),
    ),
)

@Composable
fun QubeeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = QubeeColorScheme,
        typography = QubeeTypography,
        content = content,
    )
}

@Composable
fun QubeeScreen(
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit,
) {
    Surface(color = QubeePalette.Void) {
        Box(
            modifier = modifier
                .fillMaxSize()
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            QubeePalette.Cyan.copy(alpha = 0.24f),
                            QubeePalette.Blue.copy(alpha = 0.10f),
                            Color.Transparent,
                        ),
                        center = Offset(80f, 80f),
                        radius = 980f,
                    ),
                )
                .drawBehind {
                    val grid = 44.dp.toPx()
                    var x = 0f
                    while (x <= size.width) {
                        drawLine(
                            color = QubeePalette.Cyan.copy(alpha = 0.045f),
                            start = Offset(x, 0f),
                            end = Offset(x, size.height),
                            strokeWidth = 1f,
                        )
                        x += grid
                    }
                    var y = 0f
                    while (y <= size.height) {
                        drawLine(
                            color = QubeePalette.Cyan.copy(alpha = 0.035f),
                            start = Offset(0f, y),
                            end = Offset(size.width, y),
                            strokeWidth = 1f,
                        )
                        y += grid
                    }
                    drawCircle(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                QubeePalette.Green.copy(alpha = 0.13f),
                                Color.Transparent,
                            ),
                        ),
                        radius = size.minDimension * 0.62f,
                        center = Offset(size.width * 0.92f, size.height * 0.08f),
                    )
                },
            content = content,
        )
    }
}

@Composable
fun QubeePanel(
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(20.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = QubeePalette.Panel),
        border = BorderStroke(1.dp, QubeePanelBorder),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        androidx.compose.foundation.layout.Column(
            modifier = Modifier.padding(contentPadding),
            content = content,
        )
    }
}

@Composable
fun QubeePrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = QubeePalette.Cyan,
            contentColor = QubeePalette.Void,
            disabledContainerColor = QubeePalette.PanelAlt,
            disabledContentColor = QubeePalette.MutedText,
        ),
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 14.dp),
    ) { Text(text, fontWeight = FontWeight.Bold) }
}

@Composable
fun QubeeSecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.55f)),
        colors = OutlinedButtonDefaults.outlinedButtonColors(
            contentColor = QubeePalette.Cyan,
            disabledContentColor = QubeePalette.MutedText,
        ),
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 14.dp),
    ) { Text(text, fontWeight = FontWeight.Bold) }
}

@Composable
fun QubeeStatusPill(
    text: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        color = QubeePalette.Cyan.copy(alpha = 0.10f),
        border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.35f)),
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            color = QubeePalette.Cyan,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
fun QubeeHeroMark(
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .size(88.dp)
            .background(
                brush = Brush.radialGradient(
                    colors = listOf(
                        QubeePalette.Cyan.copy(alpha = 0.32f),
                        QubeePalette.Blue.copy(alpha = 0.16f),
                        Color.Transparent,
                    ),
                ),
                shape = CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Surface(
            modifier = Modifier.size(68.dp),
            shape = CircleShape,
            color = QubeePalette.PanelAlt.copy(alpha = 0.92f),
            border = BorderStroke(1.5.dp, QubeeQuantumBrush),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    text = "Q",
                    color = QubeePalette.Cyan,
                    style = MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Black,
                )
            }
        }
    }
}

@Composable
fun QubeeMutedText(
    text: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        modifier = modifier,
        color = QubeePalette.MutedText,
        style = MaterialTheme.typography.bodyMedium,
    )
}
