package com.qubee.messenger.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val DarkColors = darkColorScheme(
    primary = QubeePrimary,
    onPrimary = QubeeBackgroundDark,
    primaryContainer = QubeePrimaryContainer,
    onPrimaryContainer = QubeeOnDark,
    secondary = QubeeSecondary,
    onSecondary = QubeeBackgroundDark,
    tertiary = QubeeTertiary,
    onTertiary = QubeeBackgroundDark,
    error = QubeeDanger,
    background = QubeeBackgroundDark,
    onBackground = QubeeOnDark,
    surface = QubeeSurfaceDark,
    onSurface = QubeeOnDark,
    surfaceVariant = QubeeSurfaceVariantDark,
    onSurfaceVariant = QubeeMuted,
    outline = QubeeOutline,
)

private val QubeeShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

@Composable
fun QubeeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = QubeeTypography,
        shapes = QubeeShapes,
        content = content,
    )
}
