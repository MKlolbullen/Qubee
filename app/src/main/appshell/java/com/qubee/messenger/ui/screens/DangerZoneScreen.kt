package com.qubee.messenger.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.components.QubeeChipTone
import com.qubee.messenger.ui.components.QubeePanel
import com.qubee.messenger.ui.components.QubeeSectionHeader
import com.qubee.messenger.ui.components.QubeeStatusChip

@Composable
fun DangerZoneScreen(
    onConfirmNuke: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmation by remember { mutableStateOf("") }

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        QubeeSectionHeader(
            title = "Danger zone",
            subtitle = "Destroy local database state, keystore-wrapped vault material, and native caches on this device. A small controlled apocalypse, not a decorative button.",
        )

        QubeePanel(title = "What this wipes") {
            QubeeStatusChip(label = "Irreversible", tone = QubeeChipTone.Danger)
            Text("SQLCipher database file", style = MaterialTheme.typography.bodyMedium)
            Text("Wrapped passphrase and master-key access", style = MaterialTheme.typography.bodyMedium)
            Text("JNI-side ephemeral state and local preferences", style = MaterialTheme.typography.bodyMedium)
        }

        QubeePanel(title = "Confirmation") {
            Text(
                text = "Type NUKE DEVICE to continue. If this button is ever too easy to press, congratulations, you have built a liability with rounded corners.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = confirmation,
                onValueChange = { confirmation = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Type confirmation") },
                placeholder = { Text("NUKE DEVICE") },
                singleLine = true,
            )
            Button(
                onClick = onConfirmNuke,
                enabled = confirmation == "NUKE DEVICE",
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Nuke this device")
            }
        }
    }
}
