package com.qubee.messenger.transport

import org.junit.Assert.assertEquals
import org.junit.Test

class HistoryReconciliationTest {
    @Test
    fun normalizeSortsAndDeduplicatesHistoryArtifacts() {
        val sync = RelayHistorySync(
            relaySessionId = "relay-1",
            syncedUntil = 999L,
            envelopes = listOf(
                RelayEnvelope("m-2", "c", "alice", "bob", "s", "bbb", "alg", 30L),
                RelayEnvelope("m-1", "c", "alice", "bob", "s", "aaa", "alg", 10L),
                RelayEnvelope("m-1", "c", "alice", "bob", "s", "aaa", "alg", 10L),
            ),
            contactRequests = listOf(
                RelayContactRequest("r-2", "alice", "bob", "Alice", "bundle", "fp", 40L),
                RelayContactRequest("r-1", "alice", "bob", "Alice", "bundle", "fp", 20L),
                RelayContactRequest("r-1", "alice", "bob", "Alice", "bundle", "fp", 20L),
            ),
            receipts = listOf(
                RelayReceipt("rc-2", "m-2", "c", "alice", "bob", "d2", "delivered", 50L),
                RelayReceipt("rc-1", "m-1", "c", "alice", "bob", "d1", "read", 25L),
                RelayReceipt("rc-1", "m-1", "c", "alice", "bob", "d1", "read", 25L),
            ),
            readCursors = listOf(
                RelayReadCursor("cur-2", "c", "bob", "d2", 40L, 55L),
                RelayReadCursor("cur-1", "c", "bob", "d1", 20L, 35L),
                RelayReadCursor("cur-1", "c", "bob", "d1", 20L, 35L),
            ),
        )

        val normalized = HistoryReconciliation.normalize(sync)

        assertEquals(listOf("m-1", "m-2"), normalized.envelopes.map { it.messageId })
        assertEquals(listOf("r-1", "r-2"), normalized.contactRequests.map { it.requestId })
        assertEquals(listOf("rc-1", "rc-2"), normalized.receipts.map { it.receiptId })
        assertEquals(listOf("cur-1", "cur-2"), normalized.readCursors.map { it.cursorId })
    }

    @Test
    fun normalizePreservesSyncBoundaryMetadata() {
        val sync = RelayHistorySync(
            relaySessionId = "relay-9",
            syncedUntil = 12345L,
            envelopes = emptyList(),
            contactRequests = emptyList(),
            receipts = emptyList(),
            readCursors = emptyList(),
        )

        val normalized = HistoryReconciliation.normalize(sync)

        assertEquals("relay-9", normalized.relaySessionId)
        assertEquals(12345L, normalized.syncedUntil)
    }
}
