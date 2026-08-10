from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# DAO: active-inbound replay lookup, compare-and-set receipt cache, soft-delete
# hygiene. Outbound ACK lookup remains separate and can still find soft-deleted
# outbound rows if a late receipt arrives.
# ---------------------------------------------------------------------------
replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''    @Query(\n        "SELECT * FROM messages " +\n            "WHERE wireId = :wireId AND conversationId = :conversationId LIMIT 1"\n    )\n    abstract suspend fun getMessageByWireIdForConversation(\n        wireId: String,\n        conversationId: String,\n    ): Message?\n\n    /// Persist the exact encrypted direct receipt produced for an inbound text.\n''',
    '''    @Query(\n        "SELECT * FROM messages " +\n            "WHERE wireId = :wireId AND conversationId = :conversationId LIMIT 1"\n    )\n    abstract suspend fun getMessageByWireIdForConversation(\n        wireId: String,\n        conversationId: String,\n    ): Message?\n\n    /// Receipt-replay lookup is deliberately narrower than the generic wire-id\n    /// lookup: only a live inbound row is evidence that this device should\n    /// answer an exact ciphertext replay. Soft-deleted rows are invisible.\n    @Query(\n        "SELECT * FROM messages " +\n            "WHERE wireId = :wireId AND isFromMe = 0 AND isDeleted = 0 LIMIT 1"\n    )\n    abstract suspend fun getActiveInboundMessageByWireId(wireId: String): Message?\n\n    /// Persist the exact encrypted direct receipt produced for an inbound text.\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''    @Query(\n        "UPDATE messages SET wireBytes = :receiptWire " +\n            "WHERE id = :messageId AND isFromMe = 0"\n    )\n    abstract suspend fun cacheInboundDirectReceipt(messageId: String, receiptWire: ByteArray)\n''',
    '''    @Query(\n        "UPDATE messages SET wireBytes = :receiptWire " +\n            "WHERE id = :messageId AND isFromMe = 0 AND isDeleted = 0 AND wireBytes IS NULL"\n    )\n    abstract suspend fun cacheInboundDirectReceipt(\n        messageId: String,\n        receiptWire: ByteArray,\n    ): Int\n''',
)

replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/database/dao/MessageDao.kt",
    '''    @Query("UPDATE messages SET isDeleted = 1, deletedAt = :deletedAt WHERE id = :messageId")\n    abstract suspend fun markMessageAsDeleted(messageId: String, deletedAt: Long)\n''',
    '''    @Query(\n        "UPDATE messages SET isDeleted = 1, deletedAt = :deletedAt, " +\n            "wireBytes = CASE WHEN isFromMe = 0 THEN NULL ELSE wireBytes END " +\n            "WHERE id = :messageId"\n    )\n    abstract suspend fun markMessageAsDeleted(messageId: String, deletedAt: Long)\n''',
)

# Repository wrappers keep the compare-and-set result visible to the caller.
replace_once(
    "app/src/main/java/com/qubee/messenger/data/repository/MessageRepository.kt",
    '''    suspend fun getMessageByWireId(wireId: String): Message? =\n        messageDao.getMessageByWireId(wireId)\n\n    suspend fun cacheInboundDirectReceipt(messageId: String, receiptWire: ByteArray) {\n        messageDao.cacheInboundDirectReceipt(messageId, receiptWire)\n    }\n''',
    '''    suspend fun getMessageByWireId(wireId: String): Message? =\n        messageDao.getMessageByWireId(wireId)\n\n    suspend fun getActiveInboundMessageByWireId(wireId: String): Message? =\n        messageDao.getActiveInboundMessageByWireId(wireId)\n\n    suspend fun cacheInboundDirectReceipt(messageId: String, receiptWire: ByteArray): Boolean =\n        messageDao.cacheInboundDirectReceipt(messageId, receiptWire) == 1\n''',
)

# Model documentation: soft deletion explicitly destroys inbound receipt cache.
replace_once(
    "app/src/main/java/com/qubee/messenger/data/model/Models.kt",
    '''    /// inbound receipt caches never enter the normal retry queue. Outbound bytes\n    /// are cleared when the first receipt lands; inbound caches live with the\n    /// message row and disappear when that message is deleted/expired.\n''',
    '''    /// inbound receipt caches never enter the normal retry queue. Outbound bytes\n    /// are cleared when the first receipt lands; inbound caches are cleared on\n    /// soft deletion and disappear entirely when that row expires/is purged.\n''',
)

svc = Path("app/src/main/java/com/qubee/messenger/service/MessageService.kt")
text = svc.read_text()

# Imports and bounded striped locks. A fixed stripe count avoids a per-message
# Mutex map that could grow forever under hostile unique-wire traffic.
old_import = "import kotlinx.coroutines.launch\n"
if text.count(old_import) != 1:
    raise SystemExit("MessageService.kt: launch import anchor drifted")
text = text.replace(
    old_import,
    old_import + "import kotlinx.coroutines.sync.Mutex\nimport kotlinx.coroutines.sync.withLock\n",
    1,
)
old_scope = '''    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())\n    private var isRunning = false\n'''
new_scope = '''    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())\n    // Network callbacks launch concurrently. Stripe by exact direct wire id so\n    // duplicates of one ciphertext cannot race the read -> ratchet-encrypt ->\n    // receipt-cache sequence, while keeping memory bounded under hostile input.\n    private val directFrameLocks = Array(DIRECT_FRAME_LOCK_STRIPES) { Mutex() }\n    private var isRunning = false\n'''
if text.count(old_scope) != 1:
    raise SystemExit("MessageService.kt: service-scope anchor drifted")
text = text.replace(old_scope, new_scope, 1)
old_const = '''        private const val OFFLINE_RETRY_MAX_ATTEMPTS: Int = 5\n\n        /// Prekey bundles ride gossipsub, so peers offline at publish\n'''
new_const = '''        private const val OFFLINE_RETRY_MAX_ATTEMPTS: Int = 5\n        private const val DIRECT_FRAME_LOCK_STRIPES: Int = 64\n\n        /// Prekey bundles ride gossipsub, so peers offline at publish\n'''
if text.count(old_const) != 1:
    raise SystemExit("MessageService.kt: companion constant anchor drifted")
text = text.replace(old_const, new_const, 1)

# Narrow replay lookup to live inbound rows.
old_lookup = "            val prior = messageRepository.getMessageByWireId(directMessageId)\n            if (prior != null && !prior.isFromMe) {\n"
new_lookup = "            val prior = messageRepository.getActiveInboundMessageByWireId(directMessageId)\n            if (prior != null) {\n"
if text.count(old_lookup) != 1:
    raise SystemExit("MessageService.kt: prior replay lookup anchor drifted")
text = text.replace(old_lookup, new_lookup, 1)

# Wrap the entire direct-frame state transition after id parsing in a striped
# mutex. Replace direct-branch returns with local lambda returns only.
start_marker = '''            // Lost-receipt recovery: retries deliberately reuse the exact wire\n'''
end_marker = '''            return true\n        }\n\n        // v3 sender-keys group frame (QUBEE_GMS\\x03).\n'''
start = text.find(start_marker)
end = text.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("MessageService.kt: direct-frame block markers drifted")
block = text[start:end + len("            return true\n")]
if "withLock" in block:
    raise SystemExit("MessageService.kt: direct block already appears serialized")
block = block.replace("return true", "return@withLock true")
wrapped = '''            val lockIndex = Math.floorMod(directMessageId.hashCode(), directFrameLocks.size)\n            return directFrameLocks[lockIndex].withLock {\n''' + "".join("    " + line if line.strip() else line for line in block.splitlines(keepends=True)) + '''            }\n'''
text = text[:start] + wrapped + text[end + len("            return true\n"):]

# Compare-and-set cache handling. The striped lock should make a zero-row CAS
# exceptional in this single-process service, but deletion or a future caller can
# still race it; fail/reuse safely rather than overwriting a receipt.
old_cache = '''            messageRepository.cacheInboundDirectReceipt(inboundMessage.id, ackWire)\n        }\n\n        // Rust owns QUBEE_DMS routing from the frame's opaque recipient selector.\n'''
new_cache = '''            if (!messageRepository.cacheInboundDirectReceipt(inboundMessage.id, ackWire)) {\n                val persisted = messageRepository\n                    .getActiveInboundMessageByWireId(messageIdHex)\n                    ?.wireBytes\n                if (persisted == null) {\n                    Timber.w(\n                        "Direct receipt cache lost CAS for %s without a live cached row; dropping send",\n                        messageIdHex,\n                    )\n                    return\n                }\n                ackWire = persisted\n            }\n        }\n\n        // Rust owns QUBEE_DMS routing from the frame's opaque recipient selector.\n'''
if text.count(old_cache) != 1:
    raise SystemExit("MessageService.kt: receipt cache anchor drifted")
text = text.replace(old_cache, new_cache, 1)
svc.write_text(text)

# Instrumented tests: CAS semantics + deleted inbound rows cannot solicit replay.
test_path = "app/src/androidTest/java/com/qubee/messenger/data/repository/database/MessageDaoInstrumentedTest.kt"
replace_once(
    test_path,
    '''        dao.cacheInboundDirectReceipt(inbound.id, receiptWire)\n\n        val stored = dao.getMessageById(inbound.id)!!\n        assertArrayEquals(receiptWire, stored.wireBytes)\n''',
    '''        assertEquals(1, dao.cacheInboundDirectReceipt(inbound.id, receiptWire))\n        assertEquals(\n            "receipt cache is compare-and-set; a duplicate creator cannot overwrite it",\n            0,\n            dao.cacheInboundDirectReceipt(inbound.id, byteArrayOf(9, 9, 9)),\n        )\n\n        val stored = dao.getMessageById(inbound.id)!!\n        assertArrayEquals(receiptWire, stored.wireBytes)\n        assertNotNull(dao.getActiveInboundMessageByWireId(inbound.wireId!!))\n''',
)
replace_once(
    test_path,
    '''        assertTrue(\n            "inbound receipt cache must never be selected by the outbound retry query",\n            dao.getRetryableOutbound(\n                now = Long.MAX_VALUE,\n                maxAttempts = 99,\n                limit = 100,\n            ).none { it.id == inbound.id },\n        )\n    }\n\n    @Test\n    fun rows_without_wireId_are_invisible_to_wireId_lookup() = runTest {\n''',
    '''        assertTrue(\n            "inbound receipt cache must never be selected by the outbound retry query",\n            dao.getRetryableOutbound(\n                now = Long.MAX_VALUE,\n                maxAttempts = 99,\n                limit = 100,\n            ).none { it.id == inbound.id },\n        )\n\n        dao.markMessageAsDeleted(inbound.id, deletedAt = 5_000L)\n        val deleted = dao.getMessageById(inbound.id)!!\n        assertTrue(deleted.isDeleted)\n        assertNull("soft delete must destroy cached direct receipt bytes", deleted.wireBytes)\n        assertNull(\n            "soft-deleted inbound row must not answer an exact ciphertext replay",\n            dao.getActiveInboundMessageByWireId(inbound.wireId!!),\n        )\n    }\n\n    @Test\n    fun rows_without_wireId_are_invisible_to_wireId_lookup() = runTest {\n''',
)

print("direct receipt race/delete hardening applied")
