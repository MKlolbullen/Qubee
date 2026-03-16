package com.qubee.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.model.UserProfile
import com.qubee.messenger.ui.components.QubeeBrandGlyph
import com.qubee.messenger.ui.theme.*

@Composable
fun SettingsScreen(
    profile: UserProfile? = null,
    inviteShare: String? = null,
    nativeStatus: String = "ready",
    relayStatus: String = "connected",
    onOpenLinkedDevices: () -> Unit = {},
    onOpenConnectivity: () -> Unit = {},
    onOpenDangerZone: () -> Unit = {},
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark)
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        // Profile card
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .background(QubeeSurfaceVariantDark)
                .border(1.dp, QubeeOutline, MaterialTheme.shapes.medium)
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            QubeeBrandGlyph(size = 56.dp)
            Column {
                Text(
                    text = profile?.displayName ?: "Unknown",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = QubeeOnDark,
                )
                Text(
                    text = profile?.relayHandle ?: "",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = QubeeMuted,
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "Fingerprint: ${profile?.fingerprint ?: "—"}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = QubeeSubtle,
                )
            }
        }

        // Sections
        SettingsSection(title = "IDENTITY", items = listOf(
            "Display Name" to (profile?.displayName ?: "—"),
            "Relay Handle" to (profile?.relayHandle ?: "—"),
            "Device ID" to (profile?.deviceId ?: "—"),
            "Fingerprint" to (profile?.fingerprint ?: "—"),
        ))

        SettingsSection(title = "CRYPTOGRAPHIC STATUS", items = listOf(
            "Key Algorithm" to "X25519 + ML-KEM 768",
            "Signing Algorithm" to "Dilithium2",
            "Cipher Suite" to "ChaCha20-Poly1305",
            "ZK Proof" to "Active",
            "Session Ratchet" to "Double Ratchet v6",
        ))

        SettingsSection(title = "NETWORK", items = listOf(
            "Relay" to if (relayStatus == "connected") "Connected" else relayStatus,
            "WebRTC P2P" to "Available",
            "Bootstrap" to "BLE + WiFi Direct",
        ))

        // Action buttons
        SettingsActionButton(label = "Linked Devices", onClick = onOpenLinkedDevices)
        SettingsActionButton(label = "Connectivity Diagnostics", onClick = onOpenConnectivity)

        // Danger zone
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.small)
                .background(QubeeDanger.copy(alpha = 0.06f))
                .border(1.dp, QubeeDanger.copy(alpha = 0.25f), MaterialTheme.shapes.small)
                .clickable { onOpenDangerZone() }
                .padding(vertical = 16.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = "Danger Zone",
                fontWeight = FontWeight.SemiBold,
                fontSize = 15.sp,
                color = QubeeDanger,
            )
        }
    }
}

@Composable
private fun SettingsSection(
    title: String,
    items: List<Pair<String, String>>,
) {
    Column {
        Text(
            text = title,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = QubeePrimary,
            letterSpacing = 1.sp,
            modifier = Modifier.padding(bottom = 10.dp),
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.small)
                .background(QubeeSurfaceDark)
                .border(1.dp, QubeeOutline, MaterialTheme.shapes.small),
        ) {
            items.forEachIndexed { index, (label, value) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .then(
                            if (index < items.size - 1)
                                Modifier.border(width = 1.dp, color = QubeeOutline, shape = RoundedCornerShape(0.dp))
                            else Modifier
                        )
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(label, style = MaterialTheme.typography.bodySmall, color = QubeeMuted)
                    val isActive = value.lowercase().let { it == "active" || it == "connected" || it == "available" }
                    Text(
                        text = value,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = if (isActive) QubeeSecondary else QubeeOnDark,
                    )
                }
                if (index < items.size - 1) {
                    HorizontalDivider(color = QubeeOutline, thickness = 1.dp)
                }
            }
        }
    }
}

@Composable
private fun SettingsActionButton(label: String, onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.small,
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        Text(label, fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
    }
}
