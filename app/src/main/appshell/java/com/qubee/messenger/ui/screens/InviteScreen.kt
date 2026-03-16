package com.qubee.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.ui.theme.*

@Composable
fun InviteScreen(
    inviteShare: String? = null,
    notice: String? = null,
    onImportInvite: (String) -> Unit = {},
    onInviteShared: () -> Unit = {},
    onDismissNotice: () -> Unit = {},
) {
    var tab by remember { mutableIntStateOf(0) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // Tab switcher
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.small)
                .border(1.dp, QubeeOutline, MaterialTheme.shapes.small),
        ) {
            listOf("Share Invite", "Scan QR").forEachIndexed { index, label ->
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(if (tab == index) QubeePrimaryContainer else QubeeSurfaceDark)
                        .clickable { tab = index }
                        .padding(vertical = 12.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = label,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp,
                        color = if (tab == index) QubeeSecondary else QubeeMuted,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (tab == 0) {
            ShareInviteTab(inviteShare = inviteShare, onInviteShared = onInviteShared)
        } else {
            ScanQrTab()
        }

        // Notice banner
        if (!notice.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(16.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(MaterialTheme.shapes.small)
                    .background(QubeePrimaryContainer)
                    .border(1.dp, QubeePrimary.copy(alpha = 0.2f), MaterialTheme.shapes.small)
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(notice, style = MaterialTheme.typography.bodySmall, color = QubeeSecondary, modifier = Modifier.weight(1f))
                Text("✕", color = QubeeMuted, modifier = Modifier
                    .clickable { onDismissNotice() }
                    .padding(4.dp))
            }
        }
    }
}

@Composable
private fun ShareInviteTab(
    inviteShare: String?,
    onInviteShared: () -> Unit,
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        // QR code placeholder
        Box(
            modifier = Modifier
                .size(212.dp)
                .clip(MaterialTheme.shapes.medium)
                .background(MaterialTheme.colorScheme.onSurface)
                .padding(16.dp),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("QR CODE", fontFamily = FontFamily.Monospace, fontSize = 14.sp, color = QubeeBackgroundDark, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(QubeePrimary, RoundedCornerShape(8.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("QB", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface, fontSize = 16.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Invite contents
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.small)
                .background(QubeeSurfaceVariantDark)
                .border(1.dp, QubeeOutline, MaterialTheme.shapes.small)
                .padding(16.dp),
        ) {
            Text(
                text = "INVITE CONTAINS",
                style = MaterialTheme.typography.labelMedium,
                color = QubeeMuted,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 1.sp,
            )
            Spacer(modifier = Modifier.height(10.dp))
            listOf(
                "Public identity bundle",
                "ZK proof of key ownership",
                "Key binding commitment",
                "Dilithium2 signature",
            ).forEach { item ->
                Row(
                    modifier = Modifier.padding(vertical = 3.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("◆", color = QubeePrimary, fontSize = 10.sp)
                    Text(item, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = QubeeSecondary)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Button(
            onClick = onInviteShared,
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.small,
            colors = ButtonDefaults.buttonColors(
                containerColor = QubeePrimary,
                contentColor = QubeeBackgroundDark,
            ),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            Text("Copy Invite Link", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        }
    }
}

@Composable
private fun ScanQrTab() {
    Column(
        modifier = Modifier.padding(top = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(240.dp)
                .clip(MaterialTheme.shapes.medium)
                .background(QubeeSurfaceVariantDark)
                .border(2.dp, QubeeOutline, MaterialTheme.shapes.medium),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("📷", fontSize = 40.sp)
                Spacer(modifier = Modifier.height(12.dp))
                Text("Point camera at QR code", style = MaterialTheme.typography.bodySmall, color = QubeeMuted)
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = "Scanning verifies the ZK ownership proof and validates the Dilithium2 signature before accepting.",
            style = MaterialTheme.typography.bodySmall,
            color = QubeeSubtle,
            lineHeight = 18.sp,
            modifier = Modifier.widthIn(max = 280.dp),
        )
    }
}
