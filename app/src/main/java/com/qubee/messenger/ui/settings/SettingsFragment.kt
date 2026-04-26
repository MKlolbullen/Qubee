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
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
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
    val state by viewModel.state.collectAsState()
    var confirmOpen by remember { mutableStateOf(false) }

    LaunchedEffect(state) {
        if (state is SettingsResetState.Done) {
            onResetComplete()
            viewModel.acknowledgeReset()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(4.dp))
        Text(
            "Real settings (theme, network bootstrap, contact " +
                "verification) will land here as the app grows. For now " +
                "we expose the one destructive action that matters: " +
                "wiping the identity.",
            style = MaterialTheme.typography.bodySmall,
        )

        Spacer(Modifier.height(32.dp))

        Text("Identity", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            "Reset deletes the local identity keystore (private keys " +
                "and group state) and forces re-onboarding. Peers in " +
                "your existing groups will not be notified — they'll " +
                "still see your previous identity until you re-share " +
                "your new one.",
            style = MaterialTheme.typography.bodySmall,
        )

        Spacer(Modifier.height(12.dp))

        when (state) {
            SettingsResetState.Working -> {
                CircularProgressIndicator()
            }
            is SettingsResetState.Error -> {
                Text(
                    (state as SettingsResetState.Error).message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(8.dp))
                ResetButton(enabled = true) { confirmOpen = true }
            }
            else -> ResetButton(enabled = state !is SettingsResetState.Done) {
                confirmOpen = true
            }
        }
    }

    if (confirmOpen) {
        AlertDialog(
            onDismissRequest = { confirmOpen = false },
            title = { Text("Reset identity?") },
            text = {
                Text(
                    "This deletes your local private keys and group " +
                        "state. You'll be sent back to onboarding to " +
                        "generate a new identity. This can't be undone.",
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

@Composable
private fun ResetButton(enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        ),
    ) { Text("Reset identity") }
}
