package com.qubee.messenger.transport

object HistoryReconciliation {
    fun normalize(sync: RelayHistorySync): RelayHistorySync {
        return sync.copy(
            envelopes = sync.envelopes.sortedBy { it.sentAt }.distinctBy { it.messageId },
            contactRequests = sync.contactRequests.sortedBy { it.sentAt }.distinctBy { it.requestId },
            receipts = sync.receipts.sortedBy { it.recordedAt }.distinctBy { it.receiptId },
            readCursors = sync.readCursors.sortedBy { it.recordedAt }.distinctBy { it.cursorId },
        )
    }
}
