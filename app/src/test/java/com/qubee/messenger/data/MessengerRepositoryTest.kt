package com.qubee.messenger.data

import com.qubee.messenger.crypto.CryptoEngine
import com.qubee.messenger.crypto.EncryptedPayload
import com.qubee.messenger.crypto.IdentityMaterial
import com.qubee.messenger.crypto.SessionMaterial
import com.qubee.messenger.data.db.ConversationEntity
import com.qubee.messenger.data.db.IdentityEntity
import com.qubee.messenger.data.db.MessageEntity
import com.qubee.messenger.data.db.QubeeDao
import com.qubee.messenger.data.db.SessionEntity
import com.qubee.messenger.data.db.SyncStateEntity
import com.qubee.messenger.model.DeliveryState
import com.qubee.messenger.model.InvitePreview
import com.qubee.messenger.model.InviteShareBundle
import com.qubee.messenger.model.MessageSender
import com.qubee.messenger.model.NativeAvailability
import com.qubee.messenger.model.NativeBridgeStatus
import com.qubee.messenger.model.RelayConnectionState
import com.qubee.messenger.model.RelayStatus
import com.qubee.messenger.transport.RelayAuthenticator
import com.qubee.messenger.transport.RelayConfig
import com.qubee.messenger.transport.RelayContactRequest
import com.qubee.messenger.transport.RelayEnvelope
import com.qubee.messenger.transport.RelayEvent
import com.qubee.messenger.transport.RelayHistorySync
import com.qubee.messenger.transport.RelayReadCursor
import com.qubee.messenger.transport.RelayReceipt
import com.qubee.messenger.transport.RelayTransport
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

@OptIn(ExperimentalCoroutinesApi::class)
class MessengerRepositoryTest {
    @Test
    fun keyChangeOnVerifiedConversationResetsTrustAndInvalidatesSession() = runTest {
        val dao = InMemoryQubeeDao()
        val relay = FakeRelayTransport()
        val crypto = FakeCryptoEngine()
        val repository = MessengerRepository(
            dao = dao,
            cryptoEngine = crypto,
            relayTransport = relay,
            scope = backgroundScope,
        )

        dao.upsertIdentity(localIdentity())
        dao.upsertConversation(
            ConversationEntity(
                id = "conv-1",
                title = "Alice",
                subtitle = "Verified contact",
                peerHandle = "alice@qubee.local",
                peerBundleBase64 = bundle("old-fp"),
                lastMessagePreview = "hello",
                unreadCount = 0,
                isVerified = true,
                updatedAt = 10L,
            )
        )
        dao.upsertSession(session("conv-1", "alice@qubee.local"))

        repository.initialize()
        advanceUntilIdle()

        relay.emit(RelayEvent.PeerBundleReceived("alice@qubee.local", bundle("new-fp")))
        advanceUntilIdle()

        val updated = dao.getConversation("conv-1")!!
        assertFalse(updated.isVerified)
        assertTrue(updated.trustResetRequired)
        assertEquals("old-fp", updated.previousPeerFingerprint)
        assertTrue(updated.lastKeyChangeAt > 0L)
        assertTrue(updated.subtitle.contains("trust reset", ignoreCase = true))
        assertNull(dao.getSession("conv-1"))
    }

    @Test
    fun historySyncReplayDeduplicatesEnvelopesReceiptsAndReadCursors() = runTest {
        val dao = InMemoryQubeeDao()
        val relay = FakeRelayTransport()
        val crypto = FakeCryptoEngine()
        val repository = MessengerRepository(
            dao = dao,
            cryptoEngine = crypto,
            relayTransport = relay,
            scope = backgroundScope,
        )

        dao.upsertIdentity(localIdentity())
        dao.upsertConversation(
            ConversationEntity(
                id = "conv-1",
                title = "Alice",
                subtitle = "Verified contact",
                peerHandle = "alice@qubee.local",
                peerBundleBase64 = bundle("peer-fp"),
                lastMessagePreview = "old",
                unreadCount = 0,
                isVerified = true,
                updatedAt = 50L,
            )
        )
        dao.upsertSession(session("conv-1", "alice@qubee.local"))
        dao.insertMessage(
            MessageEntity(
                id = "m-local",
                conversationId = "conv-1",
                sender = MessageSender.LocalUser.name,
                body = "sent earlier",
                ciphertextBase64 = "cipher-local",
                algorithm = "fake",
                timestamp = 50L,
                deliveryState = DeliveryState.Sent.name,
                isEncrypted = true,
                originDeviceId = "device-self",
            )
        )

        repository.initialize()
        advanceUntilIdle()

        val inbound = RelayEnvelope(
            messageId = "m-inbound",
            conversationId = "conv-1",
            senderHandle = "alice@qubee.local",
            recipientHandle = "victor@qubee.local",
            sessionId = "sess-alice@qubee.local",
            ciphertextBase64 = "cipher-inbound",
            algorithm = "fake",
            sentAt = 100L,
            senderDeviceId = "peer-device-1",
        )
        val receipt = RelayReceipt(
            receiptId = "rc-1",
            messageId = "m-local",
            conversationId = "conv-1",
            senderHandle = "victor@qubee.local",
            recipientHandle = "alice@qubee.local",
            recipientDeviceId = "peer-device-1",
            receiptType = "read",
            recordedAt = 110L,
        )
        val cursor = RelayReadCursor(
            cursorId = "cur-1",
            conversationId = "conv-1",
            handle = "alice@qubee.local",
            deviceId = "peer-device-1",
            readThroughTimestamp = 50L,
            recordedAt = 111L,
        )

        relay.emit(
            RelayEvent.HistorySyncReceived(
                RelayHistorySync(
                    relaySessionId = "relay-1",
                    syncedUntil = 200L,
                    envelopes = listOf(inbound, inbound),
                    contactRequests = emptyList(),
                    receipts = listOf(receipt, receipt),
                    readCursors = listOf(cursor, cursor),
                )
            )
        )
        advanceUntilIdle()

        val messages = dao.messagesForConversation("conv-1")
        assertEquals(2, messages.size)
        val restored = dao.getMessage("m-inbound")
        assertNotNull(restored)
        assertEquals("decrypted:cipher-inbound", restored?.body)

        val local = dao.getMessage("m-local")!!
        assertEquals(DeliveryState.Read.name, local.deliveryState)
        assertEquals(1, local.readByDeviceCount)
        assertEquals(1, local.deliveredToDeviceCount)

        val conversation = dao.getConversation("conv-1")!!
        assertEquals(1, conversation.unreadCount)
        assertTrue(conversation.updatedAt >= 111L)

        val syncState = dao.getSyncState()!!
        assertEquals(200L, syncState.lastHistorySyncAt)
        assertEquals("relay-1", syncState.lastRelaySessionId)
    }

    @Test
    fun markVerifiedAndResetTrustInvalidateSessionEndToEnd() = runTest {
        val dao = InMemoryQubeeDao()
        val relay = FakeRelayTransport()
        val crypto = FakeCryptoEngine()
        val repository = MessengerRepository(
            dao = dao,
            cryptoEngine = crypto,
            relayTransport = relay,
            scope = backgroundScope,
        )

        dao.upsertIdentity(localIdentity())
        dao.upsertConversation(
            ConversationEntity(
                id = "conv-1",
                title = "Alice",
                subtitle = "Imported contact",
                peerHandle = "alice@qubee.local",
                peerBundleBase64 = bundle("peer-fp"),
                lastMessagePreview = "hello",
                unreadCount = 0,
                isVerified = false,
                updatedAt = 10L,
            )
        )
        dao.upsertSession(session("conv-1", "alice@qubee.local"))

        val safetyCode = repository.markConversationVerified("conv-1")
        val verified = dao.getConversation("conv-1")!!
        assertEquals("1111 2222", safetyCode)
        assertTrue(verified.isVerified)
        assertFalse(verified.trustResetRequired)
        assertTrue(verified.subtitle.contains("verified", ignoreCase = true))
        assertNotNull(dao.getSession("conv-1"))

        val resetMessage = repository.resetConversationTrust("conv-1")
        val reset = dao.getConversation("conv-1")!!
        assertTrue(resetMessage.contains("Trust reset", ignoreCase = true))
        assertFalse(reset.isVerified)
        assertFalse(reset.trustResetRequired)
        assertTrue(reset.subtitle.contains("Trust reset locally", ignoreCase = true))
        assertNull(dao.getSession("conv-1"))
    }

    private fun localIdentity(): IdentityEntity = IdentityEntity(
        displayName = "Victor",
        deviceLabel = "Pixel",
        identityFingerprint = "self-fp",
        publicBundleBase64 = bundle("self-fp"),
        identityBundleBase64 = "identity-self",
        relayHandle = "victor@qubee.local",
        deviceId = "device-self",
        nativeBacked = false,
        createdAt = 1L,
    )

    private fun session(conversationId: String, peerHandle: String): SessionEntity = SessionEntity(
        conversationId = conversationId,
        sessionId = "sess-$peerHandle",
        peerHandle = peerHandle,
        keyMaterialBase64 = "key-$peerHandle",
        nativeBacked = false,
        state = "ShellActive",
        createdAt = 1L,
        lastUsedAt = 1L,
    )

    private fun bundle(fingerprint: String): String {
        val json = "{" +
            "\"schema\":\"qubee.public.bundle.v1\"," +
            "\"identityFingerprint\":\"$fingerprint\"," +
            "\"relayHandle\":\"alice@qubee.local\"" +
            "}"
        return Base64.getEncoder().encodeToString(json.toByteArray())
    }
}

private class FakeCryptoEngine : CryptoEngine {
    override fun status(): NativeBridgeStatus = NativeBridgeStatus(NativeAvailability.Ready, "ready")

    override fun initializeIfPossible(): NativeBridgeStatus = status()

    override fun createIdentity(displayName: String): IdentityMaterial = IdentityMaterial(
        displayName = displayName,
        deviceLabel = "Android device",
        identityFingerprint = "self-fp",
        publicBundleBase64 = "public-self",
        identityBundleBase64 = "identity-self",
        relayHandle = "victor@qubee.local",
        deviceId = "device-self",
        nativeBacked = false,
    )

    override fun restoreIdentity(identity: IdentityMaterial): Boolean = true

    override fun signRelayChallenge(identity: IdentityMaterial, challenge: String, relaySessionId: String): String = "sig"

    override fun exportInvite(identity: IdentityMaterial): InviteShareBundle = InviteShareBundle(
        payloadText = "invite",
        relayHandle = identity.relayHandle,
        identityFingerprint = identity.identityFingerprint,
        shareLabel = "label",
        bootstrapToken = "token",
    )

    override fun inspectInvitePayload(payloadText: String): InvitePreview = InvitePreview(
        displayName = "Alice",
        relayHandle = "alice@qubee.local",
        deviceId = "peer-device-1",
        identityFingerprint = "peer-fp",
        publicBundleBase64 = "peer-bundle",
        bootstrapToken = "token",
    )

    override fun computeSafetyCode(identity: IdentityMaterial, peerPublicBundleBase64: String): String = "1111 2222"

    override fun createSession(
        conversationId: String,
        peerHandle: String,
        selfPublicBundleBase64: String,
        peerPublicBundleBase64: String,
    ): SessionMaterial = SessionMaterial(
        conversationId = conversationId,
        sessionId = "sess-$peerHandle",
        peerHandle = peerHandle,
        keyMaterialBase64 = "key-$peerHandle",
        nativeBacked = false,
        state = "ShellActive",
    )

    override fun encryptMessage(session: SessionMaterial, plaintext: String): EncryptedPayload = EncryptedPayload(
        ciphertextBase64 = "cipher:$plaintext",
        algorithm = "fake",
    )

    override fun decryptMessage(session: SessionMaterial, payload: EncryptedPayload): String = "decrypted:${payload.ciphertextBase64}"

    override fun generateDemoPeerBundle(seed: String): String = "bundle:$seed"

    override fun deriveBootstrapToken(relayHandle: String, deviceId: String, identityFingerprint: String): String = "bootstrap-token"
}

private class FakeRelayTransport : RelayTransport {
    private val eventFlow = MutableSharedFlow<RelayEvent>()
    private val statusFlow = MutableStateFlow(RelayStatus(RelayConnectionState.Disconnected, "idle", "ws://test"))

    override val events: SharedFlow<RelayEvent> = eventFlow
    override val status: StateFlow<RelayStatus> = statusFlow

    val publishedReceipts = mutableListOf<RelayReceipt>()
    val publishedReadCursors = mutableListOf<RelayReadCursor>()
    val publishedEnvelopes = mutableListOf<RelayEnvelope>()

    override suspend fun connect(config: RelayConfig, authenticator: RelayAuthenticator?) {
        statusFlow.value = RelayStatus(RelayConnectionState.Connected, "connected", config.relayUrl)
    }

    override suspend fun disconnect() {
        statusFlow.value = RelayStatus(RelayConnectionState.Disconnected, "disconnected", statusFlow.value.relayUrl)
    }

    override suspend fun publish(envelope: RelayEnvelope): Boolean {
        publishedEnvelopes += envelope
        return true
    }

    override suspend fun publishContactRequest(request: RelayContactRequest): Boolean = true

    override suspend fun publishReceipt(receipt: RelayReceipt): Boolean {
        publishedReceipts += receipt
        return true
    }

    override suspend fun publishReadCursor(cursor: RelayReadCursor): Boolean {
        publishedReadCursors += cursor
        return true
    }

    override suspend fun requestPeerBundle(peerHandle: String): Boolean = true

    override suspend fun requestHistorySync(since: Long): Boolean = true

    suspend fun emit(event: RelayEvent) {
        eventFlow.emit(event)
    }
}

private class InMemoryQubeeDao : QubeeDao {
    private val identityState = MutableStateFlow<IdentityEntity?>(null)
    private val conversationsState = MutableStateFlow<Map<String, ConversationEntity>>(emptyMap())
    private val messagesState = MutableStateFlow<Map<String, MessageEntity>>(emptyMap())
    private val sessionsState = MutableStateFlow<Map<String, SessionEntity>>(emptyMap())
    private val syncState = MutableStateFlow<SyncStateEntity?>(null)

    override fun observeIdentity(id: String): Flow<IdentityEntity?> = identityState
    override suspend fun getIdentity(id: String): IdentityEntity? = identityState.value
    override suspend fun upsertIdentity(identity: IdentityEntity) {
        identityState.value = identity
    }

    override fun observeConversations(): Flow<List<ConversationEntity>> = conversationsState.map { map ->
        map.values.sortedByDescending { it.updatedAt }
    }

    override fun observeConversation(conversationId: String): Flow<ConversationEntity?> = conversationsState.map { it[conversationId] }
    override suspend fun getConversation(conversationId: String): ConversationEntity? = conversationsState.value[conversationId]
    override suspend fun getConversationByPeerHandle(peerHandle: String): ConversationEntity? = conversationsState.value.values.firstOrNull { it.peerHandle == peerHandle }

    override suspend fun upsertConversation(conversation: ConversationEntity) {
        conversationsState.update { it + (conversation.id to conversation) }
    }

    override suspend fun upsertConversations(conversations: List<ConversationEntity>) {
        conversations.forEach { upsertConversation(it) }
    }

    override suspend fun conversationCount(): Int = conversationsState.value.size

    override suspend fun clearUnread(conversationId: String) {
        val conversation = conversationsState.value[conversationId] ?: return
        upsertConversation(conversation.copy(unreadCount = 0))
    }

    override fun observeMessages(conversationId: String): Flow<List<MessageEntity>> = messagesState.map { map ->
        map.values.filter { it.conversationId == conversationId }.sortedBy { it.timestamp }
    }

    override suspend fun getMessage(messageId: String): MessageEntity? = messagesState.value[messageId]

    override suspend fun insertMessage(message: MessageEntity) {
        messagesState.update { it + (message.id to message) }
    }

    override suspend fun updateMessageState(messageId: String, deliveryState: String) {
        val message = messagesState.value[messageId] ?: return
        insertMessage(message.copy(deliveryState = deliveryState))
    }

    override suspend fun getMessagesBySenderAndStates(sender: String, states: List<String>): List<MessageEntity> =
        messagesState.value.values.filter { it.sender == sender && it.deliveryState in states }.sortedBy { it.timestamp }

    override suspend fun getMessagesUpToTimestamp(conversationId: String, sender: String, timestamp: Long): List<MessageEntity> =
        messagesState.value.values
            .filter { it.conversationId == conversationId && it.sender == sender && it.timestamp <= timestamp }
            .sortedBy { it.timestamp }

    override fun observePendingOutboundCount(conversationId: String, sender: String, states: List<String>): Flow<Int> = messagesState.map { map ->
        map.values.count { it.conversationId == conversationId && it.sender == sender && it.deliveryState in states }
    }

    override fun observeLatestMessageTimestamp(conversationId: String): Flow<Long?> = messagesState.map { map ->
        map.values.filter { it.conversationId == conversationId }.maxOfOrNull { it.timestamp }
    }

    override suspend fun getLatestMessageTimestampBySender(conversationId: String, sender: String): Long? =
        messagesState.value.values.filter { it.conversationId == conversationId && it.sender == sender }.maxOfOrNull { it.timestamp }

    override suspend fun getSession(conversationId: String): SessionEntity? = sessionsState.value[conversationId]
    override fun observeSession(conversationId: String): Flow<SessionEntity?> = sessionsState.map { it[conversationId] }

    override suspend fun upsertSession(session: SessionEntity) {
        sessionsState.update { it + (session.conversationId to session) }
    }

    override suspend fun deleteSession(conversationId: String) {
        sessionsState.update { it - conversationId }
    }

    override suspend fun getSyncState(id: String): SyncStateEntity? = syncState.value
    override fun observeSyncState(id: String): Flow<SyncStateEntity?> = syncState
    override suspend fun upsertSyncState(syncState: SyncStateEntity) {
        this.syncState.value = syncState
    }

    suspend fun messagesForConversation(conversationId: String): List<MessageEntity> =
        messagesState.value.values.filter { it.conversationId == conversationId }.sortedBy { it.timestamp }
}
