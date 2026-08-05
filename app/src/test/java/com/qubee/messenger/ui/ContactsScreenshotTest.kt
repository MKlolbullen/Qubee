package com.qubee.messenger.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.contacts.ContactSummaryUi
import com.qubee.messenger.ui.contacts.ContactsBody
import com.qubee.messenger.ui.contacts.EmptyContacts
import com.qubee.messenger.ui.theme.QubeeScreen
import org.junit.Rule
import org.junit.Test

/** Baselines for the contacts list: populated (verified/online mix + a
 * blocked entry) and the empty first-run state. */
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
        verified: Boolean,
        online: Boolean,
        initials: String,
        lastSeen: Long? = null,
    ) = ContactSummaryUi(
        contactId = id,
        displayName = name,
        identityIdHex = "aa".repeat(32),
        isVerified = verified,
        isOnline = online,
        initials = initials,
        lastSeenEpochMillis = lastSeen,
    )

    @Test
    fun contacts_populated() {
        host {
            androidx.compose.foundation.layout.Box(Modifier.padding(16.dp)) {
                ContactsBody(
                    active = listOf(
                        contact("1", "Ada Lovelace", verified = true, online = true, initials = "AL"),
                        contact("2", "Alan Turing", verified = false, online = false, initials = "AT", lastSeen = 1_700_000_000_000L),
                        contact("3", "Grace Hopper", verified = true, online = false, initials = "GH", lastSeen = 1_700_000_000_000L),
                    ),
                    blocked = listOf(
                        contact("9", "Spam Sender", verified = false, online = false, initials = "SS"),
                    ),
                    onContactClick = {},
                    onDeleteContact = {},
                    onBlockContact = {},
                    onUnblockContact = {},
                    onVerifyContact = {},
                )
            }
        }
    }

    @Test
    fun contacts_empty() {
        host { EmptyContacts(onAddContactClick = {}) }
    }
}
