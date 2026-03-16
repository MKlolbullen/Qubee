package com.qubee.messenger.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.qubee.messenger.model.NativeBridgeStatus
import com.qubee.messenger.model.RelayStatus
import com.qubee.messenger.model.VaultLockState
import com.qubee.messenger.model.VaultStatus
import com.qubee.messenger.ui.components.QubeeChipTone
import com.qubee.messenger.ui.components.QubeePanel
import com.qubee.messenger.ui.components.QubeeSectionHeader
import com.qubee.messenger.ui.components.QubeeBrandLockup
import com.qubee.messenger.ui.components.QubeeStatusChip

@Composable
fun UnlockScreen(
    vaultStatus: VaultStatus,
    nativeStatus: NativeBridgeStatus,
    relayStatus: RelayStatus,
    onUnlock: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        QubeeBrandLockup(
            title = "QUBEE",
            subtitle = "Post-quantum secure messaging",
            glyphSize = 74.dp,
        )
        Spacer(Modifier.height(18.dp))
        QubeeStatusChip(
            label = if (vaultStatus.hasExistingVault) "Vault locked" else "Prepare vault",
            tone = QubeeChipTone.Positive,
        )
        Spacer(Modifier.height(18.dp))
        QubeeSectionHeader(
            title = if (vaultStatus.hasExistingVault) "Unlock Qubee" else "Prepare Qubee vault",
            subtitle = if (vaultStatus.hasExistingVault) {
                "Authenticate to open SQLCipher, restore the local identity, and wake the transport state without pretending the app was unlocked all along."
            } else {
                "Authenticate once so Qubee can create the keystore-wrapped passphrase and initialize the secure local vault like a civilized application."
            },
        )
        Spacer(Modifier.height(24.dp))
        QubeePanel(title = "Secure vault status") {
            Text(vaultStatus.details, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Native bridge", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Text(nativeStatus.details, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Transport bootstrap", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Text(relayStatus.details, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = onUnlock,
            enabled = vaultStatus.state != VaultLockState.Unlocking,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (vaultStatus.state == VaultLockState.Unlocking) {
                CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp)
            } else {
                Icon(Icons.Rounded.Fingerprint, contentDescription = null)
            }
            Spacer(Modifier.width(10.dp))
            Text(
                text = when (vaultStatus.state) {
                    VaultLockState.Locked -> if (vaultStatus.hasExistingVault) "Unlock with biometrics" else "Unlock and prepare vault"
                    VaultLockState.Unlocking -> "Authenticating…"
                    VaultLockState.Unlocked -> "Vault unlocked"
                    VaultLockState.Error -> "Try again"
                },
                modifier = Modifier.padding(start = 10.dp),
            )
        }
        Spacer(Modifier.height(10.dp))
        OutlinedButton(onClick = onUnlock, enabled = vaultStatus.state != VaultLockState.Unlocking, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Rounded.Lock, contentDescription = null)
            Text(
                text = if (vaultStatus.hasExistingVault) "Use device credential" else "Initialize secure vault",
                modifier = Modifier.padding(start = 10.dp),
            )
        }
    }
}
