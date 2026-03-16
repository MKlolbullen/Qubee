package com.qubee.messenger.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.model.LinkedDeviceRecord
import com.qubee.messenger.model.UserProfile
import com.qubee.messenger.ui.components.QubeeChipTone
import com.qubee.messenger.ui.components.QubeePanel
import com.qubee.messenger.ui.components.QubeeSectionHeader
import com.qubee.messenger.ui.components.QubeeStatusChip
import com.qubee.messenger.ui.components.QubeeBrandGlyph

@Composable
fun LinkedDevicesScreen(
    profile: UserProfile?,
    linkedDevices: List<LinkedDeviceRecord>,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        QubeeSectionHeader(
            title = "Linked devices",
            subtitle = "One identity, multiple pieces of hardware, and a strong preference for not lying about which device did what.",
        )

        QubeePanel(title = "Primary device") {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.PhoneAndroid, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                Column {
                    Text(profile?.deviceLabel ?: "Current device", style = MaterialTheme.typography.titleMedium)
                    Text(profile?.deviceId ?: "Device id pending", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                QubeeStatusChip(label = "Primary", tone = QubeeChipTone.Positive)
                QubeeStatusChip(label = "Trusted", tone = QubeeChipTone.Positive)
            }
        }

        QubeePanel(title = "Known device records") {
            if (linkedDevices.isEmpty()) {
                Text(
                    text = "No device records yet beyond the local profile. As more transport and trust signals arrive, this list will stop being polite and become specific.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                linkedDevices.forEach { device ->
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Rounded.PhoneAndroid, contentDescription = null, tint = if (device.isTrusted) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant)
                        Column(modifier = Modifier.weight(1f)) {
                            Text(device.title, style = MaterialTheme.typography.titleSmall)
                            Text(device.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        QubeeStatusChip(
                            label = device.trustLabel,
                            tone = if (device.isTrusted) QubeeChipTone.Positive else QubeeChipTone.Warning,
                        )
                    }
                }
            }
        }

        QubeePanel(title = "Linking flow") {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                QubeeBrandGlyph(size = 40.dp)
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Secondary-device enrollment is staged next.", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "The screen now exists as a truthful placeholder instead of a decorative dead button. Wire the actual device-linking ceremony here when the protocol path is ready.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Button(onClick = {}, enabled = false, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Rounded.Link, contentDescription = null)
                Text(" Linking flow coming next")
            }
        }
    }
}
