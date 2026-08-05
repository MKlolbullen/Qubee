package com.qubee.messenger.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.groups.GroupMemberInfo
import com.qubee.messenger.ui.chat.MemberList
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeeTheme
import androidx.compose.foundation.background
import androidx.compose.material3.Surface
import org.junit.Rule
import org.junit.Test

/** Baseline for the group-details member roster (the body of the
 * bottom sheet). Rendered from the owner's perspective so the manage
 * affordances — promote/remove/transfer — are all visible. */
class GroupMembersScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private val me = "11".repeat(32)

    private fun member(idByte: String, name: String, role: String, active: Boolean = true) =
        GroupMemberInfo(
            identityIdHex = idByte.repeat(32),
            displayName = name,
            role = role,
            isActive = active,
            joinedAt = 1_700_000_000L,
        )

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshot {
            QubeeTheme {
                Surface {
                    Column(
                        Modifier
                            .fillMaxSize()
                            .background(QubeePalette.Panel)
                            .padding(horizontal = 22.dp, vertical = 18.dp),
                    ) { content() }
                }
            }
        }
    }

    @Test
    fun member_list_owner_view() {
        host {
            MemberList(
                members = listOf(
                    GroupMemberInfo(me, "You", "Owner", true, 1_700_000_000L),
                    member("22", "Grace Hopper", "Admin"),
                    member("33", "Alan Turing", "Moderator"),
                    member("44", "Ada Lovelace", "Member"),
                    member("55", "Guest Observer", "Observer"),
                ),
                myIdentityIdHex = me,
                canManage = true,
                canPromote = true,
                onRemoveMember = {},
                onPromoteMember = { _, _ -> },
                onTransferOwnership = {},
            )
        }
    }
}
