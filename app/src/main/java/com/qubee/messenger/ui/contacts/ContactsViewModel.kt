package com.qubee.messenger.ui.contacts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.ContactRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Address-book ViewModel. Distinct from [com.qubee.messenger.ui.main.ConversationsViewModel]
 * — that one observes the conversations table for the inbox surface;
 * this one observes [ContactRepository.getAllContactsFlow] for the
 * full alphabetical address book (no message-history join).
 *
 * Maps the storage-layer [Contact] entity to a UI-shaped
 * [ContactSummaryUi] — keeps Compose ignorant of which fields are
 * persistence vs. derived (initials, verified-flag boolean from
 * `trustLevel == VERIFIED`, etc.).
 */
@HiltViewModel
class ContactsViewModel @Inject constructor(
    private val contactRepository: ContactRepository,
) : ViewModel() {

    val uiState: StateFlow<ContactsUiState> = contactRepository
        .getAllContactsFlow()
        .map { contacts ->
            ContactsUiState(
                contacts = contacts.map { it.toSummary() },
            )
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000L),
            initialValue = ContactsUiState(isLoading = true),
        )

    /// Delete a contact row outright. Doesn't touch the underlying
    /// Rust group state (the contact may still be a member of a
    /// group on the Rust side — removing them from the group is a
    /// separate ceremony driven by `nativeRemoveMember`). What this
    /// does is drop the address-book row, so the contact stops
    /// appearing in lists and routing falls back to libp2p PeerId
    /// keying on subsequent inbound messages from them.
    fun deleteContact(contactId: String) {
        viewModelScope.launch {
            contactRepository.deleteContact(contactId)
        }
    }

    /// Mark a contact as blocked. Inbound from a blocked contact
    /// still goes through the receive-path TOFU population (their
    /// peerId stamp), but the block flag is what UI surfaces query
    /// to suppress notifications / hide their messages from the
    /// inbox.
    fun blockContact(contactId: String) {
        viewModelScope.launch {
            contactRepository.blockContact(contactId)
        }
    }

    private fun Contact.toSummary(): ContactSummaryUi {
        val name = displayName.ifBlank { identityId.take(8) }
        val initials = name
            .split(' ', '\t', '\n')
            .mapNotNull { it.firstOrNull()?.toString()?.uppercase() }
            .take(2)
            .joinToString(separator = "")
            .ifBlank { name.take(2).uppercase() }
        return ContactSummaryUi(
            contactId = id,
            displayName = name,
            identityIdHex = identityId,
            isVerified = trustLevel == TrustLevel.VERIFIED,
            isOnline = isOnline,
            initials = initials,
            lastSeenEpochMillis = lastSeen,
        )
    }
}

data class ContactsUiState(
    val isLoading: Boolean = false,
    val contacts: List<ContactSummaryUi> = emptyList(),
)

data class ContactSummaryUi(
    val contactId: String,
    val displayName: String,
    val identityIdHex: String,
    val isVerified: Boolean,
    val isOnline: Boolean,
    val initials: String,
    /// Epoch milliseconds. Null for contacts that have never been
    /// observed online — we default to "Last seen offline" in the
    /// row subtitle in that case.
    val lastSeenEpochMillis: Long?,
)
