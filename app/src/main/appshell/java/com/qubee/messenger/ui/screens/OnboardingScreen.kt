package com.qubee.messenger.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.ui.components.QubeeBrandGlyph
import com.qubee.messenger.ui.components.StatusChip
import com.qubee.messenger.ui.theme.*

@Composable
fun OnboardingScreen(
    nativeStatus: String = "ready",
    relayStatus: String = "connected",
    onCreateIdentity: (displayName: String, handle: String) -> Unit = { _, _ -> },
) {
    var step by remember { mutableIntStateOf(0) }
    var displayName by remember { mutableStateOf("") }
    var relayHandle by remember { mutableStateOf("") }
    var generating by remember { mutableStateOf(false) }

    AnimatedContent(targetState = step, label = "onboarding") { currentStep ->
        when (currentStep) {
            0 -> WelcomeStep(
                onCreateNew = { step = 1 },
                onRestore = { step = 1 },
            )
            1 -> IdentityCreationStep(
                displayName = displayName,
                onDisplayNameChange = { displayName = it },
                relayHandle = relayHandle,
                onRelayHandleChange = { relayHandle = it },
                generating = generating,
                onBack = { step = 0 },
                onGenerate = {
                    generating = true
                    onCreateIdentity(displayName, relayHandle)
                },
            )
        }
    }
}

@Composable
private fun WelcomeStep(
    onCreateNew: () -> Unit,
    onRestore: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark)
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        QubeeBrandGlyph(size = 140.dp)

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "QUBEE",
            fontSize = 28.sp,
            fontWeight = FontWeight.ExtraBold,
            fontFamily = FontFamily.Monospace,
            color = QubeePrimary,
            letterSpacing = 3.sp,
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "End-to-end encrypted messaging secured by post-quantum cryptography. No phone number. No server trust. Just math.",
            style = MaterialTheme.typography.bodyMedium,
            color = QubeeMuted,
            lineHeight = 22.sp,
            modifier = Modifier.widthIn(max = 320.dp),
        )

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = onCreateNew,
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.small,
            colors = ButtonDefaults.buttonColors(
                containerColor = QubeePrimary,
                contentColor = QubeeBackgroundDark,
            ),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            Text("Create Identity", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        }

        Spacer(modifier = Modifier.height(12.dp))

        OutlinedButton(
            onClick = onRestore,
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.small,
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            Text("Restore from Backup", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        }

        Spacer(modifier = Modifier.height(32.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatusChip(label = "ML-KEM 768", ok = true)
            StatusChip(label = "Dilithium2", ok = true)
            StatusChip(label = "ChaCha20", ok = true)
        }
    }
}

@Composable
private fun IdentityCreationStep(
    displayName: String,
    onDisplayNameChange: (String) -> Unit,
    relayHandle: String,
    onRelayHandleChange: (String) -> Unit,
    generating: Boolean,
    onBack: () -> Unit,
    onGenerate: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        QubeeBrandGlyph(size = 80.dp)

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "Your identity is generated locally. No data leaves your device.",
            style = MaterialTheme.typography.bodySmall,
            color = QubeeMuted,
        )

        Spacer(modifier = Modifier.height(24.dp))

        QubeeTextField(label = "Display Name", value = displayName, onValueChange = onDisplayNameChange, placeholder = "Alice")

        Spacer(modifier = Modifier.height(16.dp))

        QubeeTextField(label = "Relay Handle", value = relayHandle, onValueChange = onRelayHandleChange, placeholder = "alice@qubee")

        Spacer(modifier = Modifier.height(20.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.small)
                .background(QubeeSurfaceVariantDark)
                .border(1.dp, QubeeOutline, MaterialTheme.shapes.small)
                .padding(16.dp),
        ) {
            Text(
                text = "KEY GENERATION",
                style = MaterialTheme.typography.labelMedium,
                color = QubeeSecondary,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp,
            )
            Spacer(modifier = Modifier.height(10.dp))

            listOf(
                "X25519 Diffie-Hellman keypair",
                "Dilithium2 signing keypair",
                "ML-KEM 768 encapsulation keypair",
                "ZK proof of key ownership",
            ).forEach { item ->
                Row(
                    modifier = Modifier.padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("✓", color = QubeePrimary, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                    Text(item, style = MaterialTheme.typography.bodySmall, color = QubeeMuted, fontFamily = FontFamily.Monospace)
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = onGenerate,
            enabled = displayName.isNotBlank() && relayHandle.isNotBlank() && !generating,
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.small,
            colors = ButtonDefaults.buttonColors(
                containerColor = QubeePrimary,
                contentColor = QubeeBackgroundDark,
            ),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            Text(
                text = if (generating) "Generating keys…" else "Generate Identity",
                fontWeight = FontWeight.SemiBold,
                fontSize = 15.sp,
            )
        }
    }
}

@Composable
private fun QubeeTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = QubeeMuted,
            modifier = Modifier.padding(bottom = 6.dp),
        )
        BasicTextField(
            value = value,
            onValueChange = onValueChange,
            textStyle = MaterialTheme.typography.bodyLarge.copy(color = QubeeOnDark),
            cursorBrush = SolidColor(QubeePrimary),
            singleLine = true,
            decorationBox = { innerTextField ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(MaterialTheme.shapes.extraSmall)
                        .background(QubeeSurfaceVariantDark)
                        .border(1.dp, QubeeOutline, MaterialTheme.shapes.extraSmall)
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                ) {
                    if (value.isEmpty()) {
                        Text(placeholder, style = MaterialTheme.typography.bodyLarge, color = QubeeSubtle)
                    }
                    innerTextField()
                }
            },
        )
    }
}
