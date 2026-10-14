package com.qubee.messenger.ui

import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.ui.contacts.AddContactBody
import com.qubee.messenger.ui.contacts.AddContactError
import com.qubee.messenger.ui.contacts.AddContactState
import com.qubee.messenger.ui.theme.QubeeScreen
import org.junit.Rule
import org.junit.Test

/** Baselines for Add contact: a verified code ready to save, and a
 * code that did not check out. */
class AddContactScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(state: AddContactState) {
        paparazzi.snapshotThemed {
            QubeeScreen {
                AddContactBody(state = state, onBack = {}, onSave = {}, onScan = {})
            }
        }
    }

    @Test
    fun add_contact_preview() {
        host(
            AddContactState(
                link = "qubee://identity/eyJ1c2VyX2lkIjoiZGVtbyJ9",
                bundle = IdentityBundle(
                    userId = "mira",
                    displayName = "Mira Ekholm",
                    identityIdHex = "aa".repeat(32),
                    fingerprint = "AF3C 9021 7788 D4E1 5B60 2290 1C4F 8830 6612 AAB9 0071 2F5D",
                    shareLink = "qubee://identity/eyJ1c2VyX2lkIjoiZGVtbyJ9",
                ),
            ),
        )
    }

    @Test
    fun add_contact_invalid() {
        host(AddContactState(error = AddContactError.InvalidLink))
    }
}
