package com.qubee.messenger.data.repository.database

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.repository.database.dao.MessageDao
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented integration test for [MessageDao]'s delivery-confirmation
 * persistence — `wireId` column lookup and the `deliveredAckers` set
 * semantics that [com.qubee.messenger.data.repository.MessageRepository.applyAck]
 * relies on.
 *
 * Uses an in-memory Room database (no SQLCipher passphrase needed) so
 * the test is hermetic; the Keystore-derived key path is exercised
 * separately by `SqlCipherKeyProviderTest`. The schema this opens is
 * the live one — adding a column to `Message` without bumping the
 * Room version, or forgetting to register the `List<String>`
 * converter, would fail this test before it ever ran a query.
 */
@RunWith(AndroidJUnit4::class)
class MessageDaoInstrumentedTest {

    private lateinit var db: QubeeDatabase
    private lateinit var dao: MessageDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, QubeeDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.messageDao()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun roundtrip_preserves_wireId_and_empty_acker_list() = runTest {
        val msg = Message(
            id = "row-1",
            conversationId = "g1",
            senderId = "me",
            content = "hello",
            contentType = MessageType.TEXT,
            timestamp = 1_000L,
            status = MessageStatus.SENT,
            isFromMe = true,
            wireId = "0123456789abcdef0123456789abcdef",
        )
        dao.insertMessage(msg)

        val byId = dao.getMessageById("row-1")
        assertNotNull(byId)
        assertEquals("0123456789abcdef0123456789abcdef", byId!!.wireId)
        assertTrue("freshly-inserted row has no ackers yet", byId.deliveredAckers.isEmpty())

        val byWireId = dao.getMessageByWireId("0123456789abcdef0123456789abcdef")
        assertNotNull("getMessageByWireId must round-trip", byWireId)
        assertEquals("row-1", byWireId!!.id)
    }

    @Test
    fun lookup_by_unknown_wireId_returns_null() = runTest {
        // No row in the table at all.
        val nope = dao.getMessageByWireId("ffffffffffffffffffffffffffffffff")
        assertNull(nope)

        // Even with another row present, lookup of a non-matching id
        // must return null — guards against accidental SELECT-without-
        // WHERE regression.
        val msg = Message(
            id = "row-2",
            conversationId = "g1",
            senderId = "me",
            wireId = "11111111111111111111111111111111",
        )
        dao.insertMessage(msg)
        val stillNope = dao.getMessageByWireId("ffffffffffffffffffffffffffffffff")
        assertNull(stillNope)
    }

    @Test
    fun deliveredAckers_persists_across_update_via_replace_strategy() = runTest {
        // The `applyAck` flow does:
        //   row = dao.getMessageByWireId(...) ?: return false
        //   dao.updateMessage(row.copy(deliveredAckers = row.deliveredAckers + ...))
        // Verifies that updateMessage on a row produced from
        // .copy(...) persists both the new acker list AND the
        // existing wireId (regression guard for the old Room
        // OnConflictStrategy.IGNORE bug class).
        val msg = Message(
            id = "row-3",
            conversationId = "g1",
            senderId = "me",
            wireId = "22222222222222222222222222222222",
            status = MessageStatus.SENT,
        )
        dao.insertMessage(msg)

        // Simulate first ack arrival.
        val first = dao.getMessageByWireId("22222222222222222222222222222222")!!
        dao.updateMessage(
            first.copy(
                deliveredAckers = first.deliveredAckers + "alice",
                status = MessageStatus.DELIVERED,
            ),
        )

        val afterFirst = dao.getMessageByWireId("22222222222222222222222222222222")!!
        assertEquals(listOf("alice"), afterFirst.deliveredAckers)
        assertEquals(MessageStatus.DELIVERED, afterFirst.status)
        assertEquals(
            "wireId must survive updateMessage round-trip",
            "22222222222222222222222222222222",
            afterFirst.wireId,
        )

        // Second ack from a different recipient.
        dao.updateMessage(
            afterFirst.copy(
                deliveredAckers = afterFirst.deliveredAckers + "bob",
            ),
        )
        val afterSecond = dao.getMessageByWireId("22222222222222222222222222222222")!!
        assertEquals(listOf("alice", "bob"), afterSecond.deliveredAckers)

        // Repeat ack from alice — caller (applyAck in repo) is
        // responsible for dedupe; verify the DAO doesn't add its
        // own dedupe logic that would silently drop entries.
        dao.updateMessage(
            afterSecond.copy(
                deliveredAckers = afterSecond.deliveredAckers + "alice",
            ),
        )
        val afterThird = dao.getMessageByWireId("22222222222222222222222222222222")!!
        assertEquals(
            "DAO doesn't dedupe; that's the repo's job",
            listOf("alice", "bob", "alice"),
            afterThird.deliveredAckers,
        )
    }

    @Test
    fun rows_without_wireId_are_invisible_to_wireId_lookup() = runTest {
        // Pre-this-feature rows (and direct-P2P rows that don't
        // travel through the group encrypt path) carry wireId =
        // null. They should never match a non-null wireId lookup.
        val legacy = Message(
            id = "row-4",
            conversationId = "g1",
            senderId = "me",
            wireId = null,
        )
        dao.insertMessage(legacy)

        // Empty-string wireId is also not a match for null rows.
        val byEmpty = dao.getMessageByWireId("")
        assertNull(byEmpty)
        val byNullSentinel = dao.getMessageByWireId("null")
        assertNull(byNullSentinel)

        val byId = dao.getMessageById("row-4")
        assertNotNull(byId)
        assertNull(
            "legacy row has no wireId; getMessageById preserves that",
            byId!!.wireId,
        )

        val present = dao.getMessageByWireId("does-not-exist")
        assertFalse(
            "lookup of bogus wireId returned the legacy row",
            present?.id == "row-4",
        )
    }
}
