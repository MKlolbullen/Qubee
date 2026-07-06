package com.qubee.messenger.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import dagger.hilt.android.AndroidEntryPoint

/**
 * "Pick a contact to start a new chat with." Backed by the same
 * [ContactsViewModel] store as the Contacts tab; tapping a contact
 * opens the chat and pops this picker off the back stack (so Back from
 * the chat returns to wherever the picker was launched from, not to
 * the picker itself).
 */
@AndroidEntryPoint
class ContactSelectionFragment : Fragment() {

    private val viewModel: ContactsViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            val state by viewModel.uiState.collectAsStateWithLifecycle()
            ContactSelectionScreen(
                contacts = state.contacts,
                onPick = { contact ->
                    val args = Bundle().apply { putString("contactId", contact.contactId) }
                    findNavController().navigate(R.id.action_selection_to_chat, args)
                },
                onAddContact = {
                    findNavController().navigate(R.id.action_selection_to_add_contact)
                },
            )
        }
    }
}

@Composable
private fun ContactSelectionScreen(
    contacts: List<ContactSummaryUi>,
    onPick: (ContactSummaryUi) -> Unit,
    onAddContact: () -> Unit,
) {
    QubeeTheme {
        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 20.dp, vertical = 18.dp),
            ) {
                QubeeStatusPill("NEW CHAT")
                Spacer(Modifier.height(10.dp))
                Text(
                    "Choose a contact",
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Black,
                )
                Spacer(Modifier.height(16.dp))

                if (contacts.isEmpty()) {
                    EmptyState(onAddContact)
                } else {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(contacts, key = { it.contactId }) { contact ->
                            ContactPickRow(contact = contact, onClick = { onPick(contact) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyState(onAddContact: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "No contacts yet",
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(6.dp))
        QubeeMutedText("Add a contact by scanning their identity QR or pasting their invite link.")
        Spacer(Modifier.height(18.dp))
        QubeePrimaryButton(text = "Add a contact", onClick = onAddContact)
    }
}

@Composable
private fun ContactPickRow(contact: ContactSummaryUi, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(QubeePalette.PanelAlt)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(QubeePalette.Cyan.copy(alpha = 0.2f)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                contact.initials,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = contact.displayName.ifBlank { "Unnamed contact" },
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            QubeeMutedText(
                text = if (contact.isVerified) "Verified" else "Unverified",
            )
        }
    }
}
