package com.qubee.messenger.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
import com.qubee.messenger.ui.theme.QubeeSectionLabel
import com.qubee.messenger.ui.theme.QubeeTextField
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeTrust
import com.qubee.messenger.ui.theme.QubeeTrustShield
import com.qubee.messenger.ui.theme.label
import dagger.hilt.android.AndroidEntryPoint

/**
 * Address-book tab, grouped by what the user has to do about each
 * contact: confirm a changed key, confirm a new one, or nothing.
 * Tapping a row opens the chat; the trailing action on an unconfirmed
 * row opens the verification screen. Long-press keeps the rarer
 * actions (block, delete).
 *
 * The data class [ContactVerificationResult] kept at the bottom
 * stays in this file to preserve the existing
 * [com.qubee.messenger.data.repository.VerificationRepository]
 * import path.
 */
@AndroidEntryPoint
class ContactsFragment : Fragment() {

    private val viewModel: ContactsViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            val state by viewModel.uiState.collectAsStateWithLifecycle()
            ContactsScreen(
                state = state,
                onContactClick = { summary ->
                    val args = Bundle().apply { putString("contactId", summary.contactId) }
                    findNavController().navigate(R.id.action_contact_to_chat, args)
                },
                onAddContactClick = {
                    findNavController().navigate(R.id.action_contact_to_connect)
                },
                onDeleteContact = viewModel::deleteContact,
                onBlockContact = viewModel::blockContact,
                onUnblockContact = viewModel::unblockContact,
                onVerifyContact = { summary ->
                    com.qubee.messenger.ui.contacts.verification.ContactVerificationActivity
                        .launch(requireActivity(), summary.identityIdHex)
                },
            )
        }
    }
}

@Composable
private fun ContactsScreen(
    state: ContactsUiState,
    onContactClick: (ContactSummaryUi) -> Unit,
    onAddContactClick: () -> Unit,
    onDeleteContact: (String) -> Unit,
    onBlockContact: (String) -> Unit,
    onUnblockContact: (String) -> Unit,
    onVerifyContact: (ContactSummaryUi) -> Unit,
) {
    var query by remember { mutableStateOf("") }
    QubeeTheme {
        QubeeScreen {
            Column(modifier = Modifier.fillMaxSize()) {
                ContactsHeader(onAddContactClick = onAddContactClick)
                val hasContacts = state.contacts.isNotEmpty() || state.blocked.isNotEmpty()
                if (hasContacts) {
                    QubeeTextField(
                        value = query,
                        onValueChange = { query = it },
                        placeholder = stringResource(R.string.contacts_search),
                        modifier = Modifier.padding(horizontal = 20.dp),
                    )
                    Spacer(Modifier.height(4.dp))
                }
                when {
                    state.isLoading -> LoadingContacts()
                    !hasContacts -> EmptyContacts(onAddContactClick = onAddContactClick)
                    else -> {
                        val needle = query.trim()
                        val matches: (ContactSummaryUi) -> Boolean = { needle.isEmpty() || it.displayName.contains(needle, ignoreCase = true) }
                        ContactsBody(
                            active = state.contacts.filter(matches),
                            blocked = state.blocked.filter(matches),
                            onContactClick = onContactClick,
                            onDeleteContact = onDeleteContact,
                            onBlockContact = onBlockContact,
                            onUnblockContact = onUnblockContact,
                            onVerifyContact = onVerifyContact,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ContactsHeader(onAddContactClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 20.dp, end = 16.dp, top = 20.dp, bottom = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            stringResource(R.string.title_contacts),
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineMedium,
        )
        Button(
            onClick = onAddContactClick,
            modifier = Modifier.height(44.dp),
            shape = RoundedCornerShape(22.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = QubeePalette.Cyan,
                contentColor = QubeePalette.Void,
            ),
            contentPadding = PaddingValues(start = 12.dp, end = 16.dp),
        ) {
            Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.contacts_add), style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun ContactsBody(
    active: List<ContactSummaryUi>,
    blocked: List<ContactSummaryUi>,
    onContactClick: (ContactSummaryUi) -> Unit,
    onDeleteContact: (String) -> Unit,
    onBlockContact: (String) -> Unit,
    onUnblockContact: (String) -> Unit,
    onVerifyContact: (ContactSummaryUi) -> Unit,
) {
    var pendingDelete by remember { mutableStateOf<ContactSummaryUi?>(null) }
    val needsCheck = active.filter { it.trust == QubeeTrust.KeyChanged || it.trust == QubeeTrust.Compromised }
    val unconfirmed = active.filter { it.trust == QubeeTrust.Unverified }
    val confirmed = active.filter { it.trust == QubeeTrust.Verified }

    if (active.isEmpty() && blocked.isEmpty()) {
        Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
            QubeeMutedText(stringResource(R.string.contacts_no_results))
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(top = 4.dp, bottom = 24.dp),
    ) {
        section(
            label = R.string.contacts_section_check,
            color = QubeePalette.Warning,
            contacts = needsCheck,
            onContactClick = onContactClick,
            onRequestDelete = { pendingDelete = it },
            onBlock = { onBlockContact(it.contactId) },
            onVerify = onVerifyContact,
        )
        section(
            label = R.string.contacts_section_unconfirmed,
            color = QubeePalette.MutedText,
            contacts = unconfirmed,
            onContactClick = onContactClick,
            onRequestDelete = { pendingDelete = it },
            onBlock = { onBlockContact(it.contactId) },
            onVerify = onVerifyContact,
        )
        section(
            label = R.string.contacts_section_confirmed,
            color = QubeePalette.Green,
            contacts = confirmed,
            onContactClick = onContactClick,
            onRequestDelete = { pendingDelete = it },
            onBlock = { onBlockContact(it.contactId) },
            onVerify = onVerifyContact,
        )
        if (blocked.isNotEmpty()) {
            item(key = "blocked-header") {
                QubeeSectionLabel(
                    stringResource(R.string.contacts_section_blocked),
                    modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 4.dp),
                    color = QubeePalette.Danger,
                )
            }
            items(blocked, key = { "blocked-${it.contactId}" }) { contact ->
                BlockedContactRow(
                    contact = contact,
                    onUnblock = { onUnblockContact(contact.contactId) },
                )
            }
        }
    }
    val target = pendingDelete
    if (target != null) {
        ConfirmDeleteContactDialog(
            contactName = target.displayName,
            onConfirm = {
                onDeleteContact(target.contactId)
                pendingDelete = null
            },
            onDismiss = { pendingDelete = null },
        )
    }
}

private fun LazyListScope.section(
    label: Int,
    color: Color,
    contacts: List<ContactSummaryUi>,
    onContactClick: (ContactSummaryUi) -> Unit,
    onRequestDelete: (ContactSummaryUi) -> Unit,
    onBlock: (ContactSummaryUi) -> Unit,
    onVerify: (ContactSummaryUi) -> Unit,
) {
    if (contacts.isEmpty()) return
    item(key = "section-$label") {
        QubeeSectionLabel(
            stringResource(label),
            modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 4.dp),
            color = color,
        )
    }
    items(contacts, key = { "contact-${it.contactId}" }) { contact ->
        ContactRow(
            contact = contact,
            onClick = { onContactClick(contact) },
            onRequestDelete = { onRequestDelete(contact) },
            onBlock = { onBlock(contact) },
            onVerify = { onVerify(contact) },
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ContactRow(
    contact: ContactSummaryUi,
    onClick: () -> Unit,
    onRequestDelete: () -> Unit,
    onBlock: () -> Unit,
    onVerify: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    val avatarColor = when (contact.trust) {
        QubeeTrust.Verified -> QubeePalette.Cyan
        QubeeTrust.Unverified -> QubeePalette.Blue
        QubeeTrust.KeyChanged -> QubeePalette.Warning
        QubeeTrust.Compromised -> QubeePalette.Danger
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = onClick,
                onLongClick = { menuOpen = true },
            )
            .padding(horizontal = 20.dp, vertical = 10.dp)
            .heightIn(min = 48.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box {
            QubeeAvatar(initials = contact.initials, size = 44.dp, color = avatarColor)
            if (contact.isOnline) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .align(Alignment.BottomEnd)
                        .background(QubeePalette.Green, CircleShape),
                )
            }
        }
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
                if (contact.trust == QubeeTrust.Verified) {
                    QubeeTrustShield(contact.trust, size = 14.dp)
                    Spacer(Modifier.width(5.dp))
                }
                Text(
                    text = subtitleFor(contact),
                    color = when (contact.trust) {
                        QubeeTrust.KeyChanged -> QubeePalette.Warning
                        QubeeTrust.Compromised -> QubeePalette.Danger
                        else -> QubeePalette.MutedText
                    },
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        if (contact.trust == QubeeTrust.Verified) {
            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = QubeePalette.MutedText,
                modifier = Modifier.size(22.dp),
            )
        } else {
            TextButton(onClick = onVerify) {
                Text(
                    stringResource(R.string.contacts_confirm_action),
                    color = QubeePalette.Cyan,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        }
        Box {
            DropdownMenu(
                expanded = menuOpen,
                onDismissRequest = { menuOpen = false },
            ) {
                DropdownMenuItem(
                    text = {
                        Text(
                            stringResource(
                                if (contact.isVerified) R.string.contacts_menu_reverify else R.string.contacts_menu_verify,
                            ),
                        )
                    },
                    onClick = {
                        menuOpen = false
                        onVerify()
                    },
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.contacts_menu_block)) },
                    onClick = {
                        menuOpen = false
                        onBlock()
                    },
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.contacts_menu_delete)) },
                    onClick = {
                        menuOpen = false
                        onRequestDelete()
                    },
                )
            }
        }
    }
}

/**
 * The trust state is the subtitle for anything that needs doing; a
 * confirmed contact gets presence instead.
 */
@Composable
private fun subtitleFor(contact: ContactSummaryUi): String = when (contact.trust) {
    QubeeTrust.KeyChanged -> stringResource(R.string.trust_hint_key_changed, contact.displayName)
    QubeeTrust.Compromised -> stringResource(R.string.trust_hint_compromised)
    QubeeTrust.Unverified -> stringResource(R.string.trust_hint_unverified)
    QubeeTrust.Verified -> when {
        contact.isOnline -> stringResource(R.string.contacts_online)
        else -> contact.trust.label()
    }
}

@Composable
private fun BlockedContactRow(
    contact: ContactSummaryUi,
    onUnblock: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        QubeeAvatar(initials = contact.initials, size = 44.dp, color = QubeePalette.MutedText)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = contact.displayName,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            QubeeMutedText(stringResource(R.string.contacts_blocked_hint), style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = onUnblock) {
            Text(stringResource(R.string.contacts_unblock), color = QubeePalette.Cyan, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun LoadingContacts() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(color = QubeePalette.Cyan)
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun EmptyContacts(onAddContactClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 28.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.contacts_empty_title),
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.contacts_empty_body),
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        QubeePrimaryButton(
            text = stringResource(R.string.chats_add_someone),
            onClick = onAddContactClick,
            icon = Icons.Filled.Add,
        )
    }
}

@Composable
private fun ConfirmDeleteContactDialog(
    contactName: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = QubeePalette.Panel,
        titleContentColor = QubeePalette.Text,
        textContentColor = QubeePalette.MutedText,
        title = { Text(stringResource(R.string.contacts_delete_title, contactName)) },
        text = { Text(stringResource(R.string.contacts_delete_body), style = MaterialTheme.typography.bodyMedium) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.contacts_delete_ok), color = QubeePalette.Danger)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel), color = QubeePalette.MutedText) }
        },
    )
}

data class ContactVerificationResult(
    val success: Boolean,
    val contactName: String,
    val verificationMethod: String,
    val error: String? = null,
)
