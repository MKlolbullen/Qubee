package com.qubee.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qubee.messenger.model.TrustDetails
import com.qubee.messenger.ui.components.StatusChip
import com.qubee.messenger.ui.theme.*

@Composable
fun TrustDetailsScreen(
    trustDetails: TrustDetails? = null,
    onVerifyContact: () -> Unit = {},
    onResetTrust: () -> Unit = {},
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(QubeeBackgroundDark)
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        // Verification status
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(MaterialTheme.shapes.medium)
                .background(QubeeSurfaceVariantDark)
                .border(1.dp, QubeeOutline, MaterialTheme.shapes.medium)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            val verified = trustDetails?.verified == true
            Text(
                text = if (verified) "✓" else "?",
                fontSize = 40.sp,
                color = if (verified) QubeePrimary else QubeeWarning,
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = if (verified) "Verified Contact" else "Unverified Contact",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = if (verified) QubeeSecondary else QubeeWarning,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = if (verified)
                    "Safety codes match. This session uses post-quantum encryption with verified identity."
                else
                    "Compare safety codes in person or over a trusted channel to verify this contact.",
                style = MaterialTheme.typography.bodySmall,
                color = QubeeMuted,
                textAlign = TextAlign.Center,
                lineHeight = 18.sp,
            )
        }

        // Safety code
        if (trustDetails?.safetyCode != null) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(MaterialTheme.shapes.small)
                    .background(QubeeSurfaceDark)
                    .border(1.dp, QubeeOutline, MaterialTheme.shapes.small)
                    .padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = "SAFETY CODE",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = QubeePrimary,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.sp,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = trustDetails.safetyCode,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = QubeeSecondary,
                    letterSpacing = 3.sp,
                )
            }
        }

        // Session details
        Column {
            Text(
                text = "SESSION DETAILS",
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
                val items = listOf(
                    "Algorithm" to (trustDetails?.algorithm ?: "—"),
                    "Epoch" to (trustDetails?.epoch?.toString() ?: "0"),
                    "ZK Proof" to (if (trustDetails?.zkProofVerified == true) "Verified" else "Not verified"),
                    "Key Binding" to (if (trustDetails?.keyBindingValid == true) "Valid" else "Unknown"),
                    "Peer Fingerprint" to (trustDetails?.peerFingerprint ?: "—"),
                )
                items.forEachIndexed { index, (label, value) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(label, style = MaterialTheme.typography.bodySmall, color = QubeeMuted)
                        Text(
                            text = value,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            color = when {
                                value == "Verified" || value == "Valid" -> QubeeSecondary
                                value == "Not verified" || value == "Unknown" -> QubeeWarning
                                else -> QubeeOnDark
                            },
                        )
                    }
                    if (index < items.size - 1) {
                        HorizontalDivider(color = QubeeOutline, thickness = 1.dp)
                    }
                }
            }
        }

        // Encryption status chips
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
        ) {
            StatusChip(label = "E2E Encrypted", ok = true)
            StatusChip(label = "Post-Quantum", ok = trustDetails?.postQuantum == true)
        }

        // Actions
        if (trustDetails?.verified != true) {
            Button(
                onClick = onVerifyContact,
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.small,
                colors = ButtonDefaults.buttonColors(
                    containerColor = QubeePrimary,
                    contentColor = QubeeBackgroundDark,
                ),
                contentPadding = PaddingValues(vertical = 16.dp),
            ) {
                Text("Mark as Verified", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
            }
        }

        OutlinedButton(
            onClick = onResetTrust,
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.small,
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = QubeeWarning,
            ),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            Text("Reset Trust", fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
        }
    }
}
