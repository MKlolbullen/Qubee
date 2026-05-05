package com.qubee.messenger.ui.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * OOB-compare verification dialog. Two routes to the same end
 * state (TrustLevel.VERIFIED on the Contact row):
 *
 *  1. **Fingerprint compare** — user reads the local fingerprint
 *     out loud to the contact, contact dictates back what *their*
 *     device shows; user types it into the text field; tap
 *     "Verify". Routes through
 *     `qubeeManager.verifyIdentityKey` for case-/space-insensitive
 *     comparison. Mismatches keep the dialog open for retry.
 *
 *  2. **SAS compare** — both devices independently compute the
 *     same `"NNNN NNNN"` code (Rust orders the byte buffers
 *     lexicographically before the BLAKE3 hash). Users compare
 *     visually over a separate channel; tap "Codes match" if
 *     they agree. No bridge round-trip — the user's claim of a
 *     visual match IS the trust ceremony.
 *
 * SAS is rendered only if `sasCode != null`. When SAS computation
 * fails (no active identity yet, JNI not linked, etc.), the
 * fingerprint half of the dialog still works on its own.
 */
@Composable
fun VerifyContactDialog(
    contactName: String,
    localFingerprint: String,
    sasCode: String?,
    onConfirmFingerprint: (expected: String) -> Unit,
    onConfirmSasMatch: () -> Unit,
    onDismiss: () -> Unit,
) {
    var typed by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Verify $contactName") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Compare codes over a separate channel — voice call, " +
                        "in person, or another already-trusted app. The two devices " +
                        "compute the same value if no one's tampering with the link.",
                    style = MaterialTheme.typography.bodyMedium,
                )

                Text(
                    text = "Compare fingerprint",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = localFingerprint.ifBlank { "Not available" },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.titleMedium,
                    )
                }
                OutlinedTextField(
                    value = typed,
                    onValueChange = { typed = it },
                    label = { Text("Fingerprint from contact") },
                    placeholder = { Text("AABB CCDD EEFF GGHH") },
                    singleLine = false,
                    modifier = Modifier.fillMaxWidth(),
                )

                if (sasCode != null) {
                    Spacer(Modifier.height(4.dp))
                    Divider()
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Or compare a SAS code",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.primaryContainer,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                text = sasCode,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.headlineMedium,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                    Text(
                        text = "Both devices show the same 8 digits when nothing's " +
                            "intercepting. If they match, tap below.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(
                        onClick = onConfirmSasMatch,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Codes match") }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = typed.isNotBlank(),
                onClick = { onConfirmFingerprint(typed) },
            ) { Text("Verify") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
