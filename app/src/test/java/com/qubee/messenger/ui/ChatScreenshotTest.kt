package com.qubee.messenger.ui

import com.qubee.messenger.ui.chat.ChatContent
import com.qubee.messenger.ui.chat.ChatUiState
import com.qubee.messenger.ui.chat.ConversationDetailsUi
import com.qubee.messenger.ui.chat.ConversationSecurityState
import com.qubee.messenger.ui.chat.MessageDeliveryState
import com.qubee.messenger.ui.chat.UiMessage
import com.qubee.messenger.ui.chat.UiMessageType
import java.util.TimeZone
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/** Baselines for the chat: a confirmed 1:1 thread with every delivery
 * state, a group thread with sender lines, and the empty thread of a
 * contact whose safety key changed. */
class ChatScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    // Message times render through the default zone; pin it so the
    // baselines do not depend on the recording machine.
    private lateinit var originalTimeZone: TimeZone

    @Before
    fun pinTimeZone() {
        originalTimeZone = TimeZone.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
    }

    @After
    fun restoreTimeZone() {
        TimeZone.setDefault(originalTimeZone)
    }

    private val evening = 1_699_987_320_000L

    private fun message(
        id: String,
        text: String,
        fromMe: Boolean,
        minutesAgo: Int,
        status: MessageDeliveryState = if (fromMe) MessageDeliveryState.Delivered else MessageDeliveryState.Received,
        type: UiMessageType = UiMessageType.TEXT,
        sender: String = "",
    ) = UiMessage(
        id = id,
        text = text,
        isFromMe = fromMe,
        timestamp = evening - minutesAgo * 60_000L,
        type = type,
        status = status,
        senderName = sender,
    )

    private fun state(
        name: String,
        security: ConversationSecurityState,
        messages: List<UiMessage>,
        isGroup: Boolean = false,
    ) = ChatUiState(
        contactName = name,
        messages = messages,
        details = ConversationDetailsUi.placeholder(),
        securityState = security,
        isGroup = isGroup,
        peerIdentityIdHex = if (isGroup) null else "aa".repeat(32),
    )

    private fun host(uiState: ChatUiState, inputText: String) {
        paparazzi.snapshotThemed {
            ChatContent(
                uiState = uiState,
                inputText = inputText,
                onTextChanged = {},
                onSend = {},
                onAttach = {},
                onBackClick = {},
                onSecurityClick = {},
                onSecureCallClick = {},
                onSecureVideoClick = {},
                onDetailsClick = {},
            )
        }
    }

    @Test
    fun chat_direct_confirmed() {
        host(
            uiState = state(
                name = "Mira Ekholm",
                security = ConversationSecurityState.Verified,
                messages = listOf(
                    message("1", "Hey, are we still on for tonight?", fromMe = false, minutesAgo = 41),
                    message("2", "Yes! Seven at the usual place?", fromMe = true, minutesAgo = 38),
                    message("3", "Perfect. I'll bring the photos from Saturday.", fromMe = false, minutesAgo = 30),
                    message("4", "directions.pdf", fromMe = true, minutesAgo = 12, status = MessageDeliveryState.Sent, type = UiMessageType.FILE),
                    message("5", "Got it, see you at seven.", fromMe = true, minutesAgo = 0, status = MessageDeliveryState.Queued),
                ),
            ),
            inputText = "On my way",
        )
    }

    @Test
    fun chat_group() {
        host(
            uiState = state(
                name = "Climbing crew",
                security = ConversationSecurityState.Unverified,
                isGroup = true,
                messages = listOf(
                    message("1", "19:00 at the gym?", fromMe = false, minutesAgo = 90, sender = "Tomas"),
                    message("2", "Works for me.", fromMe = true, minutesAgo = 85),
                    message("3", "I'll be ten minutes late, start without me.", fromMe = false, minutesAgo = 20, sender = "Anna"),
                    message("4", "Voice note", fromMe = false, minutesAgo = 5, sender = "Tomas", type = UiMessageType.AUDIO),
                ),
            ),
            inputText = "",
        )
    }

    @Test
    fun chat_empty_key_changed() {
        host(
            uiState = state(
                name = "Sara Nyberg",
                security = ConversationSecurityState.KeyChanged,
                messages = emptyList(),
            ),
            inputText = "",
        )
    }
}
