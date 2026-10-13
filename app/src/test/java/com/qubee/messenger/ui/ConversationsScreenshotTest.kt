package com.qubee.messenger.ui

import androidx.compose.runtime.Composable
import com.qubee.messenger.ui.main.ConversationList
import com.qubee.messenger.ui.main.ConversationSummaryUi
import com.qubee.messenger.ui.main.EmptyConversations
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeTrust
import org.junit.Rule
import org.junit.Test

/** Baselines for the chats inbox: rows across the trust states, a
 * group, unread and muted markers, and the first-run empty state. */
class ConversationsScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    private fun host(content: @Composable () -> Unit) {
        paparazzi.snapshotThemed { QubeeScreen { content() } }
    }

    private fun convo(
        id: String,
        title: String,
        preview: String,
        isGroup: Boolean,
        trust: QubeeTrust?,
        unread: Int = 0,
        pinned: Boolean = false,
        muted: Boolean = false,
        timestamp: String = "18:42",
    ) = ConversationSummaryUi(
        conversationId = id,
        peerId = "peer-$id",
        title = title,
        preview = preview,
        timestamp = timestamp,
        isGroup = isGroup,
        isPinned = pinned,
        isMuted = muted,
        unreadCount = unread,
        trust = trust,
    )

    @Test
    fun conversations_populated() {
        host {
            ConversationList(
                conversations = listOf(
                    convo("1", "Mira Ekholm", "Got it, see you at seven.", false, QubeeTrust.Verified, unread = 2, pinned = true),
                    convo("2", "Lindqvist family", "Anna: Photos from Saturday", true, null, timestamp = "17:05"),
                    convo("3", "Jonas Pettersson", "Can you send the address again?", false, QubeeTrust.Unverified, timestamp = "12:30"),
                    convo("4", "Sara Nyberg", "New phone, same me", false, QubeeTrust.KeyChanged, timestamp = "Yesterday"),
                    convo("5", "Climbing crew", "Tomas: 19:00 at the gym?", true, null, muted = true, timestamp = "Mon"),
                    convo("6", "Ola Berg", "", false, QubeeTrust.Verified, timestamp = "3 Oct"),
                ),
                onConversationClick = {},
            )
        }
    }

    @Test
    fun conversations_empty() {
        host { EmptyConversations(onAddSomeone = {}, onStartContact = {}) }
    }
}
