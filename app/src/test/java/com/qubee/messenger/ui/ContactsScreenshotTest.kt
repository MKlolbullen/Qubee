package com.qubee.messenger.ui

import androidx.compose.runtime.Composable
import com.qubee.messenger.ui.contacts.ContactSummaryUi
import com.qubee.messenger.ui.contacts.ContactsBody
import com.qubee.messenger.ui.contacts.EmptyContacts
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeTrust
import org.junit.Rule
import org.junit.Test

/** Baselines for the contacts list grouped by trust state, with a
 * blocked entry, and the empty first-run state. */
class ContactsScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            QubeeScreen { content() }
        }
    }

    private fun contact(
        id: String,
        name: String,
        trust: QubeeTrust,
        online: Boolean,
        initials: String,
        lastSeen: Long? = null,
    ) = ContactSummaryUi(
        contactId = id,
        displayName = name,
        identityIdHex = "aa".repeat(32),
        trust = trust,
        isVerified = trust == QubeeTrust.Verified,
        isOnline = online,
        initials = initials,
        lastSeenEpochMillis = lastSeen,
    )

    @Test
    fun contacts_populated() {
        host {
            ContactsBody(
                active = listOf(
                    contact("1", "Sara Nyberg", QubeeTrust.KeyChanged, online = false, initials = "SN"),
                    contact("2", "Jonas Pettersson", QubeeTrust.Unverified, online = false, initials = "JP", lastSeen = 1_700_000_000_000L),
                    contact("3", "Anna Lindqvist", QubeeTrust.Verified, online = true, initials = "AL"),
                    contact("4", "Mira Ekholm", QubeeTrust.Verified, online = false, initials = "ME", lastSeen = 1_700_000_000_000L),
                ),
                blocked = listOf(
                    contact("9", "Spam Sender", QubeeTrust.Unverified, online = false, initials = "SS"),
                ),
                onContactClick = {},
                onDeleteContact = {},
                onBlockContact = {},
                onUnblockContact = {},
                onVerifyContact = {},
            )
        }
    }

    @Test
    fun contacts_empty() {
        host { EmptyContacts(onAddContactClick = {}) }
    }
}
