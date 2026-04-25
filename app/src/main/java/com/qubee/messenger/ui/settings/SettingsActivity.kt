package com.qubee.messenger.ui.settings

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint

/**
 * Standalone settings host. The bottom-nav also exposes a Settings tab,
 * so this activity is just the toolbar entry point — the actual settings
 * surface lives in [SettingsFragment]/Composables.
 */
@AndroidEntryPoint
class SettingsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize().padding(24.dp)) {
                    Text("Settings (placeholder)", style = MaterialTheme.typography.titleLarge)
                }
            }
        }
    }
}
