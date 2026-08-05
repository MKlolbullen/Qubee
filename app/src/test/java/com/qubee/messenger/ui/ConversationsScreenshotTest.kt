package com.qubee.messenger.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.qubee.messenger.ui.main.ConversationList
import com.qubee.messenger.ui.main.ConversationListSecurityState
import com.qubee.messenger.ui.main.ConversationSummaryUi
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeTheme
import org.junit.Rule
import org.junit.Test

/** Baseline for the conversations inbox: a mix of 1:1 and group rows
 * spanning the three security pill states, unread badges, and
 * pinned/muted markers. */
class ConversationsScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshot {
            QubeeTheme { QubeeScreen { content() } }
        }
    }

    private fun convo(
        id: String,
        title: String,
        preview: String,
        isGroup: Boolean,
        security: ConversationListSecurityState,
        unread: Int = 0,
        pinned: Boolean = false,
        muted: Boolean = false,
    ) = ConversationSummaryUi(
        conversationId = id,
        peerId = "peer-$id",
        title = title,
        preview = preview,
        timestamp = "09:41",
        isGroup = isGroup,
        isPinned = pinned,
        isMuted = muted,
        unreadCount = unread,
        securityState = security,
    )

    @Test
    fun conversations_populated() {
        host {
            Box(Modifier.padding(16.dp)) {
                ConversationList(
                    conversations = listOf(
                        convo("1", "Ada Lovelace", "Sent you the analytical engine notes", false, ConversationListSecurityState.PqReady, unread = 2, pinned = true),
                        convo("2", "Cipher Club", "Grace: rotating the group key now", true, ConversationListSecurityState.PqReady, unread = 5),
                        convo("3", "Alan Turing", "Tap to verify before trusting", false, ConversationListSecurityState.Unverified),
                        convo("4", "Field Ops", "Queued — peer offline", true, ConversationListSecurityState.Offline, muted = true),
                    ),
                    onConversationClick = {},
                    onStartContact = {},
                )
            }
        }
    }
}
