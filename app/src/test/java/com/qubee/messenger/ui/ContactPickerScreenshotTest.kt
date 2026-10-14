package com.qubee.messenger.ui

import androidx.compose.runtime.Composable
import com.qubee.messenger.ui.contacts.ContactPickerBody
import com.qubee.messenger.ui.contacts.ContactSummaryUi
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeTrust
import org.junit.Rule
import org.junit.Test

/** Baselines for the New chat picker: a short address book and the
 * empty state that points at Add someone. */
class ContactPickerScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed {
            QubeeScreen { content() }
        }
    }

    private fun contact(id: String, name: String, trust: QubeeTrust, initials: String) = ContactSummaryUi(
        contactId = id,
        displayName = name,
        identityIdHex = "aa".repeat(32),
        trust = trust,
        isVerified = trust == QubeeTrust.Verified,
        isOnline = false,
        initials = initials,
        lastSeenEpochMillis = null,
    )

    @Test
    fun picker_populated() {
        host {
            ContactPickerBody(
                contacts = listOf(
                    contact("1", "Anna Lindqvist", QubeeTrust.Verified, "AL"),
                    contact("2", "Jonas Pettersson", QubeeTrust.Unverified, "JP"),
                    contact("3", "Mira Ekholm", QubeeTrust.Verified, "ME"),
                    contact("4", "Sara Nyberg", QubeeTrust.KeyChanged, "SN"),
                ),
                query = "",
                onQueryChange = {},
                onBack = {},
                onPick = {},
                onAddSomeone = {},
            )
        }
    }

    @Test
    fun picker_empty() {
        host {
            ContactPickerBody(
                contacts = emptyList(),
                query = "",
                onQueryChange = {},
                onBack = {},
                onPick = {},
                onAddSomeone = {},
            )
        }
    }
}
