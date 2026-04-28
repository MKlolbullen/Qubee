package com.qubee.messenger.ui.settings

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class SettingsFragment : Fragment() {

    private val viewModel: SettingsViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent { SettingsContent(viewModel, ::routeToOnboarding) }
    }

    /**
     * After a successful reset, pop everything off the back stack and
     * land on onboarding so the user is forced through the
     * identity-creation flow again before doing anything else.
     */
    private fun routeToOnboarding() {
        val nav = findNavController()
        nav.navigate(
            R.id.onboardingFragment,
            null,
            NavOptions.Builder()
                .setPopUpTo(nav.graph.startDestinationId, /* inclusive = */ true)
                .build(),
        )
    }
}

@Composable
private fun SettingsContent(
    viewModel: SettingsViewModel,
    onResetComplete: () -> Unit,
) {
    QubeeTheme {
        val state by viewModel.state.collectAsState()
        var confirmOpen by remember { mutableStateOf(false) }

        LaunchedEffect(state) {
            if (state is SettingsResetState.Done) {
                onResetComplete()
                viewModel.acknowledgeReset()
            }
        }

        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                verticalArrangement = Arrangement.Top,
            ) {
                QubeeStatusPill("LOCAL DEVICE CONTROL")
                Spacer(Modifier.height(14.dp))
                Text(
                    "Settings",
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Black,
                )
                Spacer(Modifier.height(6.dp))
                QubeeMutedText(
                    "Theme, network bootstrap, contact verification and privacy controls belong here. Today this screen exposes the one dangerous switch that matters: destroying the local identity.",
                )

                Spacer(Modifier.height(26.dp))

                QubeePanel {
                    QubeeStatusPill("KEY MATERIAL")
                    Spacer(Modifier.height(14.dp))
                    Text("Reset identity", style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(6.dp))
                    QubeeMutedText(
                        "Reset deletes the local identity keystore, private keys and group state, then forces onboarding again. Existing peers are not notified and will still know the previous identity until you re-share the new one.",
                    )

                    Spacer(Modifier.height(18.dp))

                    when (state) {
                        SettingsResetState.Working -> {
                            CircularProgressIndicator(color = QubeePalette.Cyan)
                        }
                        is SettingsResetState.Error -> {
                            Text(
                                (state as SettingsResetState.Error).message,
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Spacer(Modifier.height(12.dp))
                            ResetButton(enabled = true) { confirmOpen = true }
                        }
                        else -> ResetButton(enabled = state !is SettingsResetState.Done) {
                            confirmOpen = true
                        }
                    }
                }
            }
        }

        if (confirmOpen) {
            AlertDialog(
                onDismissRequest = { confirmOpen = false },
                containerColor = QubeePalette.PanelAlt,
                titleContentColor = QubeePalette.Text,
                textContentColor = QubeePalette.MutedText,
                title = { Text("Reset identity?") },
                text = {
                    Text(
                        "This deletes your local private keys and group state. You'll be sent back to onboarding to generate a new identity. This can't be undone.",
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick = {
                            confirmOpen = false
                            viewModel.resetIdentity()
                        },
                    ) { Text("Reset", color = MaterialTheme.colorScheme.error) }
                },
                dismissButton = {
                    TextButton(onClick = { confirmOpen = false }) { Text("Cancel") }
                },
            )
        }
    }
}

@Composable
private fun ResetButton(enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(18.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = QubeePalette.Danger,
            contentColor = QubeePalette.Void,
            disabledContainerColor = QubeePalette.PanelAlt,
            disabledContentColor = QubeePalette.MutedText,
        ),
    ) { Text("Destroy local identity", fontWeight = FontWeight.Bold) }
}
