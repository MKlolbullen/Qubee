package com.qubee.messenger.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeTextField
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeTopBar
import com.qubee.messenger.ui.theme.QubeeTrustShield
import com.qubee.messenger.ui.theme.label
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
            var query by rememberSaveable { mutableStateOf("") }
            QubeeTheme {
                QubeeScreen {
                    ContactPickerBody(
                        contacts = state.contacts,
                        query = query,
                        onQueryChange = { query = it },
                        onBack = { findNavController().navigateUp() },
                        onPick = { contact ->
                            val args = Bundle().apply { putString("contactId", contact.contactId) }
                            findNavController().navigate(R.id.action_selection_to_chat, args)
                        },
                        onAddSomeone = { findNavController().navigate(R.id.action_selection_to_connect) },
                    )
                }
            }
        }
    }
}

/** Stateless picker, exposed for Paparazzi. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun ContactPickerBody(
    contacts: List<ContactSummaryUi>,
    query: String,
    onQueryChange: (String) -> Unit,
    onBack: () -> Unit,
    onPick: (ContactSummaryUi) -> Unit,
    onAddSomeone: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        QubeeTopBar(title = stringResource(R.string.picker_title), onBack = onBack)
        if (contacts.isEmpty()) {
            EmptyPicker(onAddSomeone)
        } else {
            PickerList(contacts, query, onQueryChange, onPick)
        }
    }
}

@Composable
private fun PickerList(
    contacts: List<ContactSummaryUi>,
    query: String,
    onQueryChange: (String) -> Unit,
    onPick: (ContactSummaryUi) -> Unit,
) {
    val shown = contacts.filter { query.isBlank() || it.displayName.contains(query.trim(), ignoreCase = true) }
    Column(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.padding(horizontal = 20.dp)) {
            QubeeMutedText(stringResource(R.string.picker_body))
            Spacer(Modifier.height(12.dp))
            QubeeTextField(
                value = query,
                onValueChange = onQueryChange,
                placeholder = stringResource(R.string.contacts_search),
            )
        }
        Spacer(Modifier.height(8.dp))
        if (shown.isEmpty()) {
            QubeeMutedText(
                text = stringResource(R.string.contacts_no_results),
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 16.dp),
            )
        } else {
            LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
                items(shown, key = { it.contactId }) { contact ->
                    PickerRow(contact = contact, onClick = { onPick(contact) })
                }
            }
        }
    }
}

@Composable
private fun EmptyPicker(onAddSomeone: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        QubeeAvatar(initials = "", size = 72.dp, icon = Icons.Outlined.Group)
        Spacer(Modifier.height(18.dp))
        Text(
            text = stringResource(R.string.contacts_empty_title),
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.contacts_empty_body),
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        QubeePrimaryButton(text = stringResource(R.string.picker_add_someone), onClick = onAddSomeone)
    }
}

@Composable
private fun PickerRow(contact: ContactSummaryUi, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QubeeAvatar(initials = contact.initials, size = 48.dp)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = contact.displayName,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(3.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                QubeeTrustShield(contact.trust, size = 14.dp)
                Spacer(Modifier.width(5.dp))
                Text(
                    text = contact.trust.label(),
                    color = contact.trust.color,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        Icon(
            imageVector = Icons.Filled.ChevronRight,
            contentDescription = null,
            tint = QubeePalette.MutedText,
            modifier = Modifier.size(22.dp),
        )
    }
}
