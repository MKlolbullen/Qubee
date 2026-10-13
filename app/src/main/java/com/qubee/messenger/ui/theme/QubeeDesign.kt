package com.qubee.messenger.ui.theme

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.R
import com.qubee.messenger.data.model.TrustLevel

object QubeePalette {
    val Void = Color(0xFF040C16)
    val Void2 = Color(0xFF07111F)
    val Panel = Color(0xFF0A1726)
    val PanelAlt = Color(0xFF102234)
    val Cyan = Color(0xFF12EAD8)
    val Blue = Color(0xFF00A7FF)
    val Green = Color(0xFF8CFF72)
    val Text = Color(0xFFEAFBFF)
    val MutedText = Color(0xFFA3BDCA)
    val Danger = Color(0xFFFF5C7A)
    val Warning = Color(0xFFFFCF5C)
}

@OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)
private fun manrope(weight: FontWeight) = Font(
    resId = R.font.manrope_variable,
    weight = weight,
    variationSettings = FontVariation.Settings(FontVariation.weight(weight.weight)),
)

val QubeeSans: FontFamily = FontFamily(
    manrope(FontWeight.Normal),
    manrope(FontWeight.Medium),
    manrope(FontWeight.SemiBold),
    manrope(FontWeight.Bold),
    manrope(FontWeight.ExtraBold),
)

val QubeeMono: FontFamily = FontFamily.Monospace

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
    outline = QubeePalette.PanelAlt,
    error = QubeePalette.Danger,
    errorContainer = Color(0xFF32101A),
    onErrorContainer = Color(0xFFFFD7DF),
)

private val QubeeTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.ExtraBold,
        fontSize = 30.sp,
        lineHeight = 35.sp,
        letterSpacing = (-0.6).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.ExtraBold,
        fontSize = 26.sp,
        lineHeight = 31.sp,
        letterSpacing = (-0.5).sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.ExtraBold,
        fontSize = 22.sp,
        lineHeight = 27.sp,
        letterSpacing = (-0.4).sp,
    ),
    titleLarge = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.ExtraBold,
        fontSize = 17.sp,
        lineHeight = 22.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Bold,
        fontSize = 15.sp,
        lineHeight = 20.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Bold,
        fontSize = 14.sp,
        lineHeight = 19.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Medium,
        fontSize = 15.sp,
        lineHeight = 21.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 17.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Bold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.Bold,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
    labelSmall = TextStyle(
        fontFamily = QubeeSans,
        fontWeight = FontWeight.ExtraBold,
        fontSize = 11.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.8.sp,
    ),
)

val QubeeQuantumBrush = Brush.linearGradient(
    colors = listOf(QubeePalette.Green, QubeePalette.Cyan, QubeePalette.Blue),
)

val QubeePanelBorder = Brush.linearGradient(
    colors = listOf(QubeePalette.PanelAlt, QubeePalette.PanelAlt),
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
                .background(QubeePalette.Void),
            content = content,
        )
    }
}

@Composable
fun QubeePanel(
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = QubeePalette.Panel),
        border = BorderStroke(1.dp, QubeePalette.PanelAlt),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(
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
    icon: ImageVector? = null,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .height(54.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = QubeePalette.Cyan,
            contentColor = QubeePalette.Void,
            disabledContainerColor = QubeePalette.PanelAlt,
            disabledContentColor = QubeePalette.MutedText,
        ),
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 0.dp),
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.ExtraBold)
    }
}

@Composable
fun QubeeSecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    icon: ImageVector? = null,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .height(50.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = QubeePalette.PanelAlt,
            contentColor = QubeePalette.Text,
            disabledContainerColor = QubeePalette.Panel,
            disabledContentColor = QubeePalette.MutedText,
        ),
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 0.dp),
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
fun QubeeDangerButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .height(48.dp),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, if (enabled) QubeePalette.Danger else QubeePalette.PanelAlt),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = QubeePalette.Danger,
            disabledContentColor = QubeePalette.MutedText,
        ),
    ) { Text(text, style = MaterialTheme.typography.titleMedium) }
}

@Composable
fun QubeeStatusPill(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = QubeePalette.Cyan,
    dot: Boolean = false,
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        color = color.copy(alpha = 0.12f),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (dot) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(color, CircleShape),
                )
                Spacer(Modifier.width(6.dp))
            }
            Text(
                text = text,
                color = color,
                style = MaterialTheme.typography.labelMedium,
            )
        }
    }
}

@Composable
fun QubeeSectionLabel(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = QubeePalette.MutedText,
) {
    Text(
        text = text,
        modifier = modifier,
        color = color,
        style = MaterialTheme.typography.labelSmall,
    )
}

@Composable
fun QubeeHeroMark(
    modifier: Modifier = Modifier,
    width: Dp = 200.dp,
) {
    Image(
        painter = painterResource(R.drawable.qubee_mark),
        contentDescription = stringResource(R.string.app_name),
        modifier = modifier.size(width = width, height = width * 361f / 560f),
        contentScale = ContentScale.Fit,
    )
}

@Composable
fun QubeeMutedText(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
) {
    Text(
        text = text,
        modifier = modifier,
        color = QubeePalette.MutedText,
        style = style,
    )
}

@Composable
fun QubeeTopBar(
    title: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {},
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(start = 4.dp, end = 12.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack, modifier = Modifier.size(44.dp)) {
            Icon(Icons.Filled.ArrowBack, contentDescription = "Back", tint = QubeePalette.Text)
        }
        Text(
            text = title,
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        actions()
    }
}

@Composable
fun QubeeIconButton(
    icon: ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    tint: Color = QubeePalette.Text,
    background: Color = QubeePalette.PanelAlt,
) {
    IconButton(
        onClick = onClick,
        modifier = modifier
            .size(44.dp)
            .background(background, CircleShape),
    ) {
        Icon(icon, contentDescription = contentDescription, tint = tint, modifier = Modifier.size(22.dp))
    }
}

@Composable
fun QubeeAvatar(
    initials: String,
    modifier: Modifier = Modifier,
    size: Dp = 48.dp,
    color: Color = QubeePalette.Cyan,
    background: Color = QubeePalette.PanelAlt,
    icon: ImageVector? = null,
) {
    Box(
        modifier = modifier
            .size(size)
            .background(background, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(size * 0.46f))
        } else {
            Text(
                text = initials,
                color = color,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
fun QubeeSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Switch(
        checked = checked,
        onCheckedChange = onCheckedChange,
        modifier = modifier,
        colors = SwitchDefaults.colors(
            checkedThumbColor = QubeePalette.Void,
            checkedTrackColor = QubeePalette.Cyan,
            checkedBorderColor = QubeePalette.Cyan,
            uncheckedThumbColor = QubeePalette.MutedText,
            uncheckedTrackColor = QubeePalette.PanelAlt,
            uncheckedBorderColor = QubeePalette.PanelAlt,
        ),
    )
}

@Composable
fun QubeeToggleRow(
    title: String,
    body: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            QubeeAvatar(initials = "", size = 40.dp, icon = icon)
            Spacer(Modifier.width(12.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(title, color = QubeePalette.Text, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(3.dp))
            QubeeMutedText(body, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.width(12.dp))
        QubeeSwitch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
fun QubeeTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    label: String? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    monospace: Boolean = false,
    enabled: Boolean = true,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.fillMaxWidth(),
        enabled = enabled,
        singleLine = singleLine,
        minLines = minLines,
        placeholder = placeholder?.let { { Text(it, color = QubeePalette.MutedText) } },
        label = label?.let { { Text(it) } },
        shape = RoundedCornerShape(14.dp),
        textStyle = if (monospace) {
            MaterialTheme.typography.bodySmall.copy(fontFamily = QubeeMono, color = QubeePalette.Text)
        } else {
            MaterialTheme.typography.bodyLarge.copy(color = QubeePalette.Text)
        },
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = QubeePalette.Text,
            unfocusedTextColor = QubeePalette.Text,
            disabledTextColor = QubeePalette.MutedText,
            focusedContainerColor = QubeePalette.Panel,
            unfocusedContainerColor = QubeePalette.Panel,
            disabledContainerColor = QubeePalette.Panel,
            cursorColor = QubeePalette.Cyan,
            focusedBorderColor = QubeePalette.Cyan,
            unfocusedBorderColor = QubeePalette.PanelAlt,
            disabledBorderColor = QubeePalette.PanelAlt,
            focusedLabelColor = QubeePalette.Cyan,
            unfocusedLabelColor = QubeePalette.MutedText,
            focusedPlaceholderColor = QubeePalette.MutedText,
            unfocusedPlaceholderColor = QubeePalette.MutedText,
        ),
    )
}

/**
 * The only trust vocabulary the UI speaks: three colours and plain
 * words. Rust and the trust policy decide the underlying level; the
 * Verified + changed-key invariant from TrustStatePolicy is what makes
 * KeyChanged its own state rather than a flavour of Unverified.
 */
enum class QubeeTrust(val color: Color, val icon: ImageVector) {
    Verified(QubeePalette.Green, Icons.Filled.GppGood),
    Unverified(QubeePalette.MutedText, Icons.Outlined.Shield),
    KeyChanged(QubeePalette.Warning, Icons.Filled.GppMaybe),
    Compromised(QubeePalette.Danger, Icons.Filled.GppBad),
    ;

    companion object {
        fun of(level: TrustLevel): QubeeTrust = when (level) {
            TrustLevel.VERIFIED -> Verified
            TrustLevel.KEY_CHANGED -> KeyChanged
            TrustLevel.COMPROMISED -> Compromised
            else -> Unverified
        }
    }
}

@Composable
fun QubeeTrust.label(): String = stringResource(
    when (this) {
        QubeeTrust.Verified -> R.string.trust_verified
        QubeeTrust.Unverified -> R.string.trust_unverified
        QubeeTrust.KeyChanged -> R.string.trust_key_changed
        QubeeTrust.Compromised -> R.string.trust_compromised
    },
)

@Composable
fun QubeeTrustShield(
    trust: QubeeTrust,
    modifier: Modifier = Modifier,
    size: Dp = 16.dp,
) {
    Icon(
        imageVector = trust.icon,
        contentDescription = trust.label(),
        tint = trust.color,
        modifier = modifier.size(size),
    )
}

fun String.qubeeInitials(): String = split(' ', '\t', '\n')
    .filter { it.isNotBlank() }
    .take(2)
    .joinToString("") { it.first().uppercaseChar().toString() }
    .ifBlank { "Q" }
