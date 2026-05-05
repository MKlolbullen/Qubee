package com.qubee.messenger.ui.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * OOB-compare verification dialog. Consumes the
 * `qubeeManager.verifyIdentityKey` JNI bridge via
 * `ChatViewModel.confirmContactVerification`.
 *
 * UX contract:
 *  * Top: the locally-computed fingerprint of the peer's identity
 *    (BLAKE3 hash, formatted as `"AABB CCDD EEFF GGHH"`). The user
 *    reads this to their contact (over a separate channel — phone,
 *    in person, etc.) so the contact can confirm a match on
 *    *their* device's matching fingerprint.
 *  * Bottom: a text field where the user enters the fingerprint
 *    their contact dictates back. Whitespace + case are normalised
 *    on the Rust side, so any mix of `"AABBCCDD..."` /
 *    `"aa bb cc dd ..."` etc. works.
 *  * Cancel: dismisses without state change.
 *  * Verify: routes through ChatViewModel.confirmContactVerification.
 *    On match: dialog auto-dismisses (ChatViewModel flips
 *    `pendingVerification = false`). On mismatch: dialog stays open
 *    for retry.
 */
@Composable
fun VerifyContactDialog(
    contactName: String,
    localFingerprint: String,
    onConfirm: (expected: String) -> Unit,
    onDismiss: () -> Unit,
) {
    var typed by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Verify $contactName") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Compare fingerprints over a separate channel — voice call, " +
                        "in person, or another already-trusted app. The two devices " +
                        "compute the same value if no one's tampering with the link.",
                    style = MaterialTheme.typography.bodyMedium,
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
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = typed,
                    onValueChange = { typed = it },
                    label = { Text("Fingerprint from contact") },
                    placeholder = { Text("AABB CCDD EEFF GGHH") },
                    singleLine = false,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = typed.isNotBlank(),
                onClick = { onConfirm(typed) },
            ) { Text("Verify") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
