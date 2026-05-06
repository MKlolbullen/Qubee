package com.qubee.messenger.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
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
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeHeroMark
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanelBorder
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import dagger.hilt.android.AndroidEntryPoint

/**
 * Address-book tab. Renders [ContactsViewModel.uiState] as a
 * vertical list of contacts; tapping a row navigates to the chat
 * with that contact. The "Add contact" button at the top routes
 * to [com.qubee.messenger.ui.contacts.AddContactFragment] for the
 * `qubee://identity/<token>` invite flow.
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
            val state by viewModel.uiState.collectAsState()
            ContactsScreen(
                state = state,
                onContactClick = { summary ->
                    val args = Bundle().apply { putString("contactId", summary.contactId) }
                    findNavController().navigate(R.id.action_contact_to_chat, args)
                },
                onAddContactClick = {
                    findNavController().navigate(R.id.action_contact_to_add_contact)
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
) {
    QubeeTheme {
        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 22.dp, vertical = 26.dp),
            ) {
                ContactsHeader(onAddContactClick = onAddContactClick)
                Spacer(Modifier.height(22.dp))

                when {
                    state.isLoading -> LoadingContacts()
                    state.contacts.isEmpty() -> EmptyContacts(onAddContactClick = onAddContactClick)
                    else -> ContactList(
                        contacts = state.contacts,
                        onContactClick = onContactClick,
                    )
                }
            }
        }
    }
}

@Composable
private fun ContactsHeader(onAddContactClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            QubeeStatusPill("ADDRESS BOOK")
            Spacer(Modifier.height(12.dp))
            Text(
                "Contacts",
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Black,
            )
            QubeeMutedText("Identities you've paired with via invite link.")
        }
        QubeeHeroMark(modifier = Modifier.size(72.dp))
    }
    Spacer(Modifier.height(18.dp))
    QubeePrimaryButton(
        text = "Add contact",
        onClick = onAddContactClick,
        modifier = Modifier.fillMaxWidth(),
    )
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
private fun EmptyContacts(onAddContactClick: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "No contacts yet",
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(8.dp))
        QubeeMutedText("Tap “Add contact” above and scan or paste an identity link.")
        Spacer(Modifier.height(20.dp))
        QubeePrimaryButton(
            text = "Add your first contact",
            onClick = onAddContactClick,
        )
    }
}

@Composable
private fun ContactList(
    contacts: List<ContactSummaryUi>,
    onContactClick: (ContactSummaryUi) -> Unit,
) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        items(contacts, key = { it.contactId }) { contact ->
            ContactRow(contact = contact, onClick = { onContactClick(contact) })
        }
    }
}

@Composable
private fun ContactRow(contact: ContactSummaryUi, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(QubeePalette.Panel.copy(alpha = 0.92f))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Avatar(initials = contact.initials, isOnline = contact.isOnline)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = contact.displayName,
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (contact.isVerified) {
                    Spacer(Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.Filled.VerifiedUser,
                        contentDescription = "Verified",
                        tint = QubeePalette.Cyan,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
            Spacer(Modifier.height(2.dp))
            QubeeMutedText(text = subtitleFor(contact))
        }
    }
}

/**
 * Build the row subtitle from online status + relative time on
 * `lastSeenEpochMillis`. Buckets are coarse on purpose — this is
 * an at-a-glance hint, not a clock.
 *
 *  * online → "Online"
 *  * `lastSeen == null` → "Last seen offline" (no timestamp ever
 *    recorded; usually means we've never received a packet from
 *    this peer since pairing).
 *  * within 1 minute → "Last seen just now"
 *  * within 1 hour → "Last seen Xm ago"
 *  * within 1 day → "Last seen Xh ago"
 *  * within 7 days → "Last seen Xd ago"
 *  * older → "Last seen on YYYY-MM-DD"
 */
private fun subtitleFor(contact: ContactSummaryUi): String {
    if (contact.isOnline) return "Online"
    val ts = contact.lastSeenEpochMillis ?: return "Last seen offline"
    val deltaSeconds = ((System.currentTimeMillis() - ts) / 1000).coerceAtLeast(0)
    return when {
        deltaSeconds < 60 -> "Last seen just now"
        deltaSeconds < 60 * 60 -> "Last seen ${deltaSeconds / 60}m ago"
        deltaSeconds < 24 * 60 * 60 -> "Last seen ${deltaSeconds / 3600}h ago"
        deltaSeconds < 7 * 24 * 60 * 60 -> "Last seen ${deltaSeconds / 86_400}d ago"
        else -> {
            val fmt = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.getDefault())
            "Last seen on ${fmt.format(java.util.Date(ts))}"
        }
    }
}

@Composable
private fun Avatar(initials: String, isOnline: Boolean) {
    Box(
        modifier = Modifier
            .size(46.dp)
            .clip(CircleShape)
            .background(QubeePalette.Cyan.copy(alpha = 0.18f))
            .border(
                width = 1.dp,
                brush = QubeePanelBorder,
                shape = CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = initials,
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        if (isOnline) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .align(Alignment.BottomEnd)
                    .clip(CircleShape)
                    .background(QubeePalette.Green),
            )
        }
    }
}

data class ContactVerificationResult(
    val success: Boolean,
    val contactName: String,
    val verificationMethod: String,
    val error: String? = null,
)
