package com.qubee.messenger.data.repository.database

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.repository.database.dao.ContactDao
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ContactDaoInstrumentedTest {
    private lateinit var db: QubeeDatabase
    private lateinit var dao: ContactDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, QubeeDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.contactDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun latest_message_is_global_and_unread_count_includes_older_inbound_messages() = runTest {
        dao.insertContact(Contact(id = "alice", identityId = "alice-key", displayName = "Alice"))
        db.messageDao().insertMessages(
            listOf(
                Message(
                    id = "old-unread",
                    conversationId = "direct-old",
                    senderId = "alice",
                    content = "older unread",
                    timestamp = 10L,
                    status = MessageStatus.DELIVERED,
                ),
                Message(
                    id = "latest",
                    conversationId = "direct-new",
                    senderId = "alice",
                    content = "latest preview",
                    timestamp = 30L,
                    status = MessageStatus.DELIVERED,
                ),
                Message(
                    id = "read",
                    conversationId = "direct-new",
                    senderId = "alice",
                    content = "already read",
                    timestamp = 20L,
                    status = MessageStatus.READ,
                ),
                Message(
                    id = "deleted",
                    conversationId = "direct-new",
                    senderId = "alice",
                    content = "deleted unread",
                    timestamp = 40L,
                    status = MessageStatus.DELIVERED,
                    isDeleted = true,
                ),
                Message(
                    id = "outbound",
                    conversationId = "direct-new",
                    senderId = "me",
                    content = "outbound",
                    timestamp = 50L,
                    status = MessageStatus.SENT,
                    isFromMe = true,
                ),
            ),
        )

        val result = dao.getContactsWithLastMessage().first().single()

        assertEquals("latest preview", result.lastMessageContent)
        assertEquals(30L, result.lastMessageTimestamp)
        assertEquals(2, result.unreadCount)
    }
}
