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
import org.junit.Assert.assertArrayEquals
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
    fun ack_is_bound_to_expected_conversation_before_retry_is_retired() = runTest {
        val sharedWireId = "abababababababababababababababab"
        val intended = Message(
            id = "bound-ack-1",
            conversationId = "direct-alice",
            senderId = "me",
            status = MessageStatus.SENT,
            isFromMe = true,
            wireId = sharedWireId,
            wireBytes = byteArrayOf(1, 2, 3),
            nextRetryAt = 10L,
        )
        dao.insertMessage(intended)

        assertTrue(
            dao.applyAckTransactional(
                sharedWireId,
                "alice-identity",
                "direct-alice",
            ) is com.qubee.messenger.data.repository.database.dao.ApplyAckResult.Applied,
        )
        val after = dao.getMessageById(intended.id)!!
        assertEquals(MessageStatus.DELIVERED, after.status)
        assertNull(after.wireBytes)
        assertNull(after.nextRetryAt)

        val wrongConversation = Message(
            id = "bound-ack-2",
            conversationId = "direct-bob",
            senderId = "me",
            status = MessageStatus.SENT,
            isFromMe = true,
            wireId = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            wireBytes = byteArrayOf(4, 5, 6),
            nextRetryAt = 20L,
        )
        dao.insertMessage(wrongConversation)
        val rejected = dao.applyAckTransactional(
            wrongConversation.wireId!!,
            "alice-identity",
            "direct-alice",
        )
        assertTrue(
            rejected is com.qubee.messenger.data.repository.database.dao.ApplyAckResult.NotFound,
        )
        val untouched = dao.getMessageById(wrongConversation.id)!!
        assertEquals(MessageStatus.SENT, untouched.status)
        assertArrayEquals(byteArrayOf(4, 5, 6), untouched.wireBytes)
        assertEquals(20L, untouched.nextRetryAt)
    }

    @Test
    fun inbound_direct_receipt_cache_roundtrips_without_entering_retry_queue() = runTest {
        val inbound = Message(
            id = "inbound-direct-1",
            conversationId = "direct-1",
            senderId = "peer",
            content = "accepted text",
            contentType = MessageType.TEXT,
            timestamp = 4_000L,
            status = MessageStatus.DELIVERED,
            isFromMe = false,
            wireId = "33333333333333333333333333333333",
        )
        dao.insertMessage(inbound)
        val receiptWire = byteArrayOf(0x51, 0x55, 0x42, 0x45, 0x45)
        assertEquals(1, dao.cacheInboundDirectReceipt(inbound.id, receiptWire))
        assertEquals(
            "receipt cache is compare-and-set; a duplicate creator cannot overwrite it",
            0,
            dao.cacheInboundDirectReceipt(inbound.id, byteArrayOf(9, 9, 9)),
        )

        val stored = dao.getMessageById(inbound.id)!!
        assertArrayEquals(receiptWire, stored.wireBytes)
        assertNotNull(dao.getActiveInboundMessageByWireId(inbound.wireId!!))
        assertTrue(
            "inbound receipt cache must never be selected by the outbound retry query",
            dao.getRetryableOutbound(
                now = Long.MAX_VALUE,
                maxAttempts = 99,
                limit = 100,
            ).none { it.id == inbound.id },
        )

        dao.markMessageAsDeleted(inbound.id, deletedAt = 5_000L)
        val deleted = dao.getMessageById(inbound.id)!!
        assertTrue(deleted.isDeleted)
        assertNull("soft delete must destroy cached direct receipt bytes", deleted.wireBytes)
        assertNull(
            "soft-deleted inbound row must not answer an exact ciphertext replay",
            dao.getActiveInboundMessageByWireId(inbound.wireId!!),
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

    @Test
    fun failed_durable_queue_update_preserves_prepared_intent_after_reopen() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = "queue-failure-${java.util.UUID.randomUUID()}.db"
        db.close()
        db = Room.databaseBuilder(context, QubeeDatabase::class.java, name).build()
        dao = db.messageDao()
        try {
            val prepared = Message(
                id = "prepared",
                conversationId = "direct-peer",
                senderId = "me",
                content = "preserve this text",
                status = MessageStatus.PREPARED,
                isFromMe = true,
            )
            dao.insertMessage(prepared)
            db.openHelper.writableDatabase.execSQL(
                "CREATE TRIGGER fail_queue BEFORE INSERT ON messages " +
                    "WHEN NEW.status = 'SENDING' BEGIN SELECT RAISE(ABORT, 'queue write failed'); END"
            )
            var rejected = false
            try {
                dao.insertMessage(
                    prepared.copy(
                        status = MessageStatus.SENDING,
                        wireId = "wire-id",
                        wireBytes = byteArrayOf(1, 2, 3),
                        nextRetryAt = 100L,
                    )
                )
            } catch (_: android.database.sqlite.SQLiteException) {
                rejected = true
            }
            assertTrue("the actual SQLite queue replacement must fail", rejected)
            db.close()
            db = Room.databaseBuilder(context, QubeeDatabase::class.java, name).build()
            dao = db.messageDao()
            assertEquals(MessageStatus.PREPARED, dao.getMessageById(prepared.id)!!.status)
            assertEquals(1, dao.failStalePreparedOutbound())
            assertEquals(0, dao.failStalePreparedOutbound())
            assertEquals(0, dao.recoverOrphanedSendingOutbound())
            val recovered = dao.getMessageById(prepared.id)!!
            assertEquals(MessageStatus.FAILED, recovered.status)
            assertEquals(prepared.content, recovered.content)
            assertEquals(prepared.conversationId, recovered.conversationId)
            assertNull(recovered.wireBytes)
            assertNull(recovered.wireId)
            assertTrue(dao.getRetryableOutbound(Long.MAX_VALUE, 99, 100).isEmpty())
        } finally {
            db.close()
            context.deleteDatabase(name)
        }
    }

    @Test
    fun durable_sending_recovery_retries_exact_bytes_and_preserves_other_states() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = "queue-recovery-${java.util.UUID.randomUUID()}.db"
        db.close()
        db = Room.databaseBuilder(context, QubeeDatabase::class.java, name).build()
        dao = db.messageDao()
        try {
            val queued = Message(
                id = "queued",
                conversationId = "direct-peer",
                senderId = "me",
                content = "queued text",
                status = MessageStatus.SENDING,
                isFromMe = true,
                wireId = "durable-wire-id",
                wireBytes = byteArrayOf(4, 5, 6),
                nextRetryAt = 100L,
                retryAttempt = 2,
            )
            val untouched = listOf(
                queued.copy(id = "inbound", isFromMe = false),
                queued.copy(id = "no-wire", wireBytes = null),
                queued.copy(id = "delivered", status = MessageStatus.DELIVERED, nextRetryAt = null),
                queued.copy(id = "inbound-prepared", status = MessageStatus.PREPARED, isFromMe = false),
            )
            for (row in listOf(queued) + untouched) dao.insertMessage(row)
            db.close()
            db = Room.databaseBuilder(context, QubeeDatabase::class.java, name).build()
            dao = db.messageDao()
            assertEquals(0, dao.failStalePreparedOutbound())
            assertEquals(1, dao.recoverOrphanedSendingOutbound())
            assertEquals(0, dao.recoverOrphanedSendingOutbound())
            assertTrue(dao.getRetryableOutbound(99L, 3, 100).isEmpty())
            val retry = dao.getRetryableOutbound(100L, 3, 100).single()
            assertEquals(queued.id, retry.id)
            assertEquals(MessageStatus.SENT, retry.status)
            assertEquals(queued.conversationId, retry.conversationId)
            assertEquals(queued.wireId, retry.wireId)
            assertEquals(queued.nextRetryAt, retry.nextRetryAt)
            assertEquals(queued.retryAttempt, retry.retryAttempt)
            assertArrayEquals(queued.wireBytes, retry.wireBytes)
            assertTrue(dao.getRetryableOutbound(100L, 2, 100).isEmpty())
            for (row in untouched) {
                val stored = dao.getMessageById(row.id)!!
                assertEquals(row.status, stored.status)
                assertArrayEquals(row.wireBytes, stored.wireBytes)
            }
        } finally {
            db.close()
            context.deleteDatabase(name)
        }
    }
}
