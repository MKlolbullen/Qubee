package com.qubee.messenger.ui.lock

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.theme.QubeeHeroMark
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme

/**
 * Full-screen lock gate shown over the app when [AppLockManager] is
 * locked. Renders the Qubee mark, a status line, an optional error
 * from a failed/cancelled attempt, and an "Unlock" button that
 * re-launches the biometric / device-credential prompt.
 *
 * Stateless by design (all state is hoisted) so it renders in
 * Paparazzi and never needs a live BiometricPrompt to draw.
 */
@Composable
fun UnlockScreen(
    error: String?,
    onUnlockClick: () -> Unit,
) {
    QubeeTheme {
        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 28.dp, vertical = 32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                QubeeHeroMark()
                Spacer(Modifier.height(24.dp))

                QubeeStatusPill("DEVICE LOCKED")
                Spacer(Modifier.height(16.dp))

                Text(
                    "Qubee is locked",
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Black,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(10.dp))
                QubeeMutedText(
                    "Verify with your fingerprint, face, or device PIN to open your conversations.",
                    modifier = Modifier.fillMaxWidth(),
                )

                if (error != null) {
                    Spacer(Modifier.height(16.dp))
                    Text(
                        error,
                        color = QubeePalette.Danger,
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                }

                Spacer(Modifier.height(28.dp))
                QubeePrimaryButton(text = "Unlock", onClick = onUnlockClick)
            }
        }
    }
}
