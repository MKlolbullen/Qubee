package com.qubee.messenger.ui

import com.qubee.messenger.groups.GroupInvite
import com.qubee.messenger.ui.groups.GroupInviteBody
import com.qubee.messenger.ui.groups.InviteUiState
import com.qubee.messenger.ui.theme.QubeeScreen
import org.junit.Rule
import org.junit.Test

/** Baselines for New group: before anything happened, after a group
 * was created (invite as a code), and after an invite was checked. */
class GroupInviteScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(state: InviteUiState, newGroupName: String = "", pastedLink: String = "") {
        paparazzi.snapshotThemed {
            QubeeScreen {
                GroupInviteBody(
                    state = state,
                    maxMembers = 16,
                    newGroupName = newGroupName,
                    onNewGroupNameChange = {},
                    pastedLink = pastedLink,
                    onPastedLinkChange = {},
                    onBack = {},
                    onCreate = {},
                    onShareInvite = {},
                    onScan = {},
                    onInspect = {},
                    onJoin = {},
                    onDiscard = {},
                )
            }
        }
    }

    @Test
    fun group_invite_start() {
        host(InviteUiState(), newGroupName = "Climbing crew")
    }

    @Test
    fun group_invite_ready() {
        host(
            InviteUiState(
                groupName = "Climbing crew",
                generatedLink = "qubee://invite/eyJncm91cF9pZF9oZXgiOiJhYWJiY2NkZCIsImdyb3VwX25hbWUiOiJDbGltYmluZyBjcmV3In0",
            ),
        )
    }

    @Test
    fun group_invite_scanned() {
        host(
            InviteUiState(
                scannedLink = "qubee://invite/eyJncm91cF9pZF9oZXgiOiJhYWJiY2NkZCJ9",
                scannedInvite = GroupInvite(
                    groupIdHex = "ab".repeat(16),
                    groupName = "Lindqvist family",
                    inviterIdHex = "cd".repeat(32),
                    inviterName = "Anna Lindqvist",
                    invitationCode = "ef".repeat(8),
                    expiresAt = null,
                    maxMembers = 16,
                ),
            ),
        )
    }
}
