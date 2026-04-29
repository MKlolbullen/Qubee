package com.qubee.messenger.ui.main

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeHeroMark
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQuantumBrush
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import dagger.hilt.android.AndroidEntryPoint

/**
 * Conversations landing screen.
 *
 * The storage/repository layer does not yet expose a conversation list flow,
 * so this pass upgrades the first-run empty state instead of pretending there
 * are chats. The real list can be dropped into the same design shell once
 * ConversationRepository exposes observable summaries.
 */
@AndroidEntryPoint
class ConversationsFragment : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            ConversationsLanding(
                onStartContact = {
                    findNavController().navigate(R.id.action_to_contact_selection)
                },
                onOpenInvites = {
                    findNavController().navigate(R.id.action_to_group_invite)
                },
            )
        }
    }
}

@Composable
private fun ConversationsLanding(
    onStartContact: () -> Unit,
    onOpenInvites: () -> Unit,
) {
    QubeeTheme {
        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 22.dp, vertical = 26.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        QubeeStatusPill("P2P MESSENGER")
                        Spacer(Modifier.height(12.dp))
                        Text(
                            "Chats",
                            color = QubeePalette.Text,
                            style = MaterialTheme.typography.headlineLarge,
                            fontWeight = FontWeight.Black,
                        )
                    }
                    QubeeHeroMark(modifier = Modifier.size(72.dp))
                }

                Spacer(Modifier.height(28.dp))

                QubeePanel {
                    EmptySignalGlyph()
                    Spacer(Modifier.height(18.dp))
                    Text(
                        "No secure channels yet",
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.headlineSmall,
                    )
                    Spacer(Modifier.height(8.dp))
                    QubeeMutedText(
                        "Add a verified contact or generate a group invite to open your first post-quantum conversation. Until then, the hive is quiet.",
                    )
                    Spacer(Modifier.height(20.dp))
                    QubeePrimaryButton(
                        text = "Choose contact",
                        onClick = onStartContact,
                    )
                    Spacer(Modifier.height(12.dp))
                    QubeeSecondaryButton(
                        text = "Create / scan group invite",
                        onClick = onOpenInvites,
                    )
                }

                Spacer(Modifier.height(18.dp))

                QubeePanel {
                    Text(
                        "Security baseline",
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.titleLarge,
                    )
                    Spacer(Modifier.height(14.dp))
                    SecurityLine(
                        icon = Icons.Default.Security,
                        title = "Local identity",
                        body = "Your private identity material stays on this device.",
                    )
                    Spacer(Modifier.height(12.dp))
                    SecurityLine(
                        icon = Icons.Default.QrCodeScanner,
                        title = "QR trust ceremony",
                        body = "First contact should be scanned or compared, not guessed from a directory.",
                    )
                    Spacer(Modifier.height(12.dp))
                    SecurityLine(
                        icon = Icons.Default.GroupAdd,
                        title = "Small groups first",
                        body = "Invite flow is intentionally explicit so group membership does not become metadata soup.",
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptySignalGlyph() {
    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = Alignment.Center,
    ) {
        Surface(
            modifier = Modifier.size(112.dp),
            shape = CircleShape,
            color = QubeePalette.Cyan.copy(alpha = 0.10f),
            border = BorderStroke(1.dp, QubeeQuantumBrush),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = QubeePalette.Cyan,
                    modifier = Modifier.size(42.dp),
                )
            }
        }
    }
}

@Composable
private fun SecurityLine(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    body: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
    ) {
        Surface(
            modifier = Modifier.size(36.dp),
            shape = CircleShape,
            color = QubeePalette.Cyan.copy(alpha = 0.10f),
            border = BorderStroke(1.dp, QubeePalette.Cyan.copy(alpha = 0.35f)),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = QubeePalette.Cyan,
                    modifier = Modifier.size(18.dp),
                )
            }
        }
        Spacer(Modifier.size(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                title,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
            )
            QubeeMutedText(body)
        }
    }
}
