package com.qubee.messenger.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.ui.components.QubeeBrandGlyph
import com.qubee.messenger.ui.theme.QubeeBackgroundDark
import com.qubee.messenger.ui.theme.QubeeGlow
import com.qubee.messenger.ui.theme.QubeeGlowStrong
import com.qubee.messenger.ui.theme.QubeeMuted
import com.qubee.messenger.ui.theme.QubeePrimary
import com.qubee.messenger.ui.theme.QubeeSurfaceVariantDark
import kotlinx.coroutines.delay

@Composable
fun SplashScreen(
    onFinished: () -> Unit,
) {
    val infiniteTransition = rememberInfiniteTransition(label = "splash")

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(600, easing = EaseInOutCubic),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "pulse",
    )

    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        visible = true
        delay(2800)
        onFinished()
    }

    val alpha by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = tween(800, easing = EaseOutCubic),
        label = "fadeIn",
    )
    val scale by animateFloatAsState(
        targetValue = if (visible) 1f else 0.85f,
        animationSpec = tween(800, easing = EaseOutCubic),
        label = "scaleIn",
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.radialGradient(
                    colors = listOf(QubeeSurfaceVariantDark, QubeeBackgroundDark),
                    radius = 800f,
                ),
            ),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier
                .alpha(alpha)
                .scale(scale),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            QubeeBrandGlyph(size = 160.dp)

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "QUBEE",
                fontSize = 32.sp,
                fontWeight = FontWeight.ExtraBold,
                fontFamily = FontFamily.Monospace,
                color = QubeePrimary,
                letterSpacing = 4.sp,
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Post-Quantum Secure Messaging",
                style = MaterialTheme.typography.bodyMedium,
                color = QubeeMuted,
                letterSpacing = 1.5.sp,
            )

            Spacer(modifier = Modifier.height(40.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                repeat(3) { index ->
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .alpha(
                                if (index == 0) pulseAlpha
                                else if (index == 1) 1f - pulseAlpha * 0.5f
                                else pulseAlpha * 0.7f
                            )
                            .background(QubeePrimary, MaterialTheme.shapes.extraLarge),
                    )
                }
            }
        }
    }
}
