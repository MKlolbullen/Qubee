package com.qubee.messenger.data

import android.util.Base64
import com.qubee.messenger.BuildConfig
import com.qubee.messenger.crypto.CryptoEngine
import com.qubee.messenger.crypto.EncryptedPayload
import com.qubee.messenger.crypto.IdentityMaterial
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.crypto.SessionMaterial
import com.qubee.messenger.data.db.ConversationEntity
import com.qubee.messenger.data.db.IdentityEntity
import com.qubee.messenger.data.db.MessageEntity
import com.qubee.messenger.data.db.QubeeDao
import com.qubee.messenger.data.db.SessionEntity
import com.qubee.messenger.data.db.SyncStateEntity
import com.qubee.messenger.model.ChatMessage
import com.qubee.messenger.model.ConversationSummary
import com.qubee.messenger.model.DeliveryState
import com.qubee.messenger.model.InviteImportResult
import com.qubee.messenger.model.InviteShareBundle
import com.qubee.messenger.model.MessageSender
import com.qubee.messenger.model.NativeBridgeStatus
import com.qubee.messenger.model.RelayStatus
import com.qubee.messenger.model.TrustDetails
import com.qubee.messenger.model.UserProfile
import com.qubee.messenger.network.p2p.BootstrapPeerHint
import com.qubee.messenger.network.p2p.BootstrapTransportPreference
import com.qubee.messenger.network.p2p.DeliveryPath
import com.qubee.messenger.network.p2p.HybridEnvelopeDispatcher
import com.qubee.messenger.network.p2p.HybridEnvelopeEvent
import com.qubee.messenger.transport.RelayAuthenticator
import com.qubee.messenger.transport.RelayAuthProof
import com.qubee.messenger.transport.RelayConfig
import com.qubee.messenger.transport.RelayContactRequest
import com.qubee.messenger.transport.RelayEnvelope
import com.qubee.messenger.transport.RelayEvent
import com.qubee.messenger.transport.RelayHello
import com.qubee.messenger.transport.RelayHistorySync
import com.qubee.messenger.transport.RelayReadCursor
import com.qubee.messenger.transport.RelayReceipt
import com.qubee.messenger.transport.HistoryReconciliation
import com.qubee.messenger.transport.RelayEnvelopeValidator
import com.qubee.messenger.transport.RelayTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

private const val NATIVE_HYBRID_INIT_ALGORITHM = "native-hybrid-init-v1"

class MessengerRepository(
    private val dao: QubeeDao,
    private val cryptoEngine: CryptoEngine,
    private val relayTransport: RelayTransport,
    private val hybridDispatcher: HybridEnvelopeDispatcher? = null,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private val nativeStatusState = MutableStateFlow(cryptoEngine.status())
    private var initialized = false

    val nativeStatus: StateFlow<NativeBridgeStatus> = nativeStatusState
    val relayStatus: StateFlow<RelayStatus> = relayTransport.status

    val profileFlow: Flow<UserProfile?> = dao.observeIdentity().map { it?.toUserProfile() }
    val conversationsFlow: Flow<List<ConversationSummary>> = dao.observeConversations().map { list -> list.map { it.toSummary() } }

    suspend fun initialize() {
        if (initialized) return
        initialized = true
        nativeStatusState.value = cryptoEngine.initializeIfPossible()
        dao.upsertSyncState(dao.getSyncState() ?: SyncStateEntity(lastHistorySyncAt = 0L, lastRelaySessionId = ""))

        val existingIdentity = dao.getIdentity()
        if (existingIdentity != null) {
            cryptoEngine.restoreIdentity(existingIdentity.toIdentityMaterial())
            restoreNativeSessionsFromDb()
            connectRelay(existingIdentity)
            hybridDispatcher?.configureLocalBootstrap(
                cryptoEngine.deriveBootstrapToken(existingIdentity.relayHandle, existingIdentity.deviceId, existingIdentity.identityFingerprint)
            )
            hybridDispatcher?.start(existingIdentity.relayHandle, existingIdentity.deviceId)
        }

        hybridDispatcher?.let { dispatcher ->
            scope.launch {
                dispatcher.events.collect { event ->
                    when (event) {
                        is HybridEnvelopeEvent.EnvelopeReceived -> handleIncomingEnvelope(event.envelope)
                        is HybridEnvelopeEvent.ReceiptReceived -> handleRelayReceipt(event.receipt)
                        is HybridEnvelopeEvent.ReadCursorReceived -> handleReadCursor(event.cursor)
                        is HybridEnvelopeEvent.TransportNotice -> Unit
                    }
                }
            }
        }

        scope.launch {
            relayTransport.events.collect { event ->
                when (event) {
                    is RelayEvent.DeliveryReceipt -> dao.updateMessageState(event.messageId, DeliveryState.Sent.name)
                    is RelayEvent.EnvelopeReceived -> handleIncomingEnvelope(event.envelope)
                    is RelayEvent.PeerBundleReceived -> updatePeerBundle(event.peerHandle, event.publicBundleBase64)
                    is RelayEvent.ContactRequestReceived -> handleIncomingContactRequest(event.request)
                    is RelayEvent.HistorySyncReceived -> applyHistorySync(event.sync)
                    is RelayEvent.ReceiptReceived -> handleRelayReceipt(event.receipt)
                    is RelayEvent.ReadCursorReceived -> handleReadCursor(event.cursor)
                    is RelayEvent.Authenticated -> {
                        nativeStatusState.value = cryptoEngine.status()
                        rememberHistoryCursor(dao.getSyncState()?.lastHistorySyncAt ?: 0L, event.relaySessionId)
                        requestHistorySync()
                        replayPendingOutbound()
                    }
                    is RelayEvent.TransportError -> Unit
                }
            }
        }
    }

    suspend fun requestHistorySync() {
        val since = dao.getSyncState()?.lastHistorySyncAt ?: 0L
        relayTransport.requestHistorySync(since)
    }

    suspend fun replayPendingOutbound() {
        val identity = dao.getIdentity() ?: return
        val pending = dao.getMessagesBySenderAndStates(
            sender = MessageSender.LocalUser.name,
            states = listOf(DeliveryState.Sending.name, DeliveryState.Sent.name, DeliveryState.Failed.name),
        )
        pending.forEach { message ->
            val conversation = dao.getConversation(message.conversationId) ?: return@forEach
            val session = dao.getSession(message.conversationId) ?: return@forEach
            val deliveryPath = hybridDispatcher?.sendEnvelope(
                RelayEnvelope(
                    messageId = message.id,
                    conversationId = message.conversationId,
                    senderHandle = identity.relayHandle,
                    recipientHandle = conversation.peerHandle,
                    sessionId = session.sessionId,
                    ciphertextBase64 = message.ciphertextBase64,
                    algorithm = message.algorithm,
                    sentAt = message.timestamp,
                    senderDeviceId = message.originDeviceId ?: identity.deviceId,
                )
            ) ?: if (relayTransport.publish(
                    RelayEnvelope(
                        messageId = message.id,
                        conversationId = message.conversationId,
                        senderHandle = identity.relayHandle,
                        recipientHandle = conversation.peerHandle,
                        sessionId = session.sessionId,
                        ciphertextBase64 = message.ciphertextBase64,
                        algorithm = message.algorithm,
                        sentAt = message.timestamp,
                        senderDeviceId = message.originDeviceId ?: identity.deviceId,
                    )
                )) DeliveryPath.Relay else DeliveryPath.Failed
            dao.updateMessageState(message.id, if (deliveryPath == DeliveryPath.Failed) DeliveryState.Failed.name else DeliveryState.Sent.name)
        }
    }

    fun conversationFlow(conversationId: String): Flow<ConversationSummary?> = dao.observeConversation(conversationId).map { it?.toSummary() }

    fun messagesFlow(conversationId: String): Flow<List<ChatMessage>> = dao.observeMessages(conversationId).map { rows -> rows.map { it.toChatMessage() } }

    fun trustDetailsFlow(conversationId: String): Flow<TrustDetails?> = combine(
        dao.observeConversation(conversationId),
        dao.observeSession(conversationId),
        dao.observePendingOutboundCount(
            conversationId,
            MessageSender.LocalUser.name,
            listOf(DeliveryState.Sending.name, DeliveryState.Sent.name, DeliveryState.Failed.name),
        ),
        dao.observeSyncState(),
        dao.observeIdentity(),
        dao.observeLatestMessageTimestamp(conversationId),
    ) { conversation, session, pendingOutbound, syncState, identity, latestMessageAt ->
        if (conversation == null || identity == null) return@combine null
        TrustDetails(
            conversationId = conversation.id,
            conversationTitle = conversation.title,
            peerHandle = conversation.peerHandle,
            localFingerprint = identity.identityFingerprint,
            peerFingerprint = bundleFingerprintFromBase64(conversation.peerBundleBase64),
            safetyCode = conversation.peerBundleBase64.takeIf { it.isNotBlank() }?.let {
                runCatching { cryptoEngine.computeSafetyCode(identity.toIdentityMaterial(), it) }.getOrNull()
            },
            isVerified = conversation.isVerified,
            trustResetRequired = conversation.trustResetRequired,
            previousPeerFingerprint = conversation.previousPeerFingerprint,
            sessionId = session?.sessionId,
            sessionState = session?.state ?: "No session yet",
            sessionNativeBacked = session?.nativeBacked ?: false,
            pendingOutboundCount = pendingOutbound,
            lastHistorySyncAt = syncState?.lastHistorySyncAt ?: 0L,
            lastSeenMessageAt = latestMessageAt ?: 0L,
            lastKeyChangeAt = conversation.lastKeyChangeAt,
            localDeviceId = identity.deviceId,
            lastReadCursorAt = conversation.lastReadCursorAt,
        )
    }

    suspend fun bootstrapIdentity(displayName: String) {
        val identity = cryptoEngine.createIdentity(displayName)
        val entity = identity.toEntity()
        dao.upsertIdentity(entity)
        dao.upsertSyncState(SyncStateEntity(lastHistorySyncAt = 0L, lastRelaySessionId = ""))
        nativeStatusState.value = cryptoEngine.status()
        connectRelay(entity)
        hybridDispatcher?.configureLocalBootstrap(
            cryptoEngine.deriveBootstrapToken(entity.relayHandle, entity.deviceId, entity.identityFingerprint)
        )
        hybridDispatcher?.start(entity.relayHandle, entity.deviceId)
    }

    suspend fun exportInviteShare(): InviteShareBundle? {
        val identity = dao.getIdentity() ?: return null
        return cryptoEngine.exportInvite(identity.toIdentityMaterial())
    }

    suspend fun importInvitePayload(payloadText: String): InviteImportResult {
        val identity = dao.getIdentity() ?: error("Create a local identity before importing invites")
        val preview = cryptoEngine.inspectInvitePayload(payloadText)
        hybridDispatcher?.registerPeerBootstrap(
            BootstrapPeerHint(
                peerHandle = preview.relayHandle,
                peerBootstrapToken = preview.bootstrapToken,
                peerDeviceId = preview.deviceId,
                preference = when (preview.preferredBootstrap) {
                    "wifi-direct-only" -> BootstrapTransportPreference.WifiDirectOnly
                    "ble-only" -> BootstrapTransportPreference.BleOnly
                    else -> BootstrapTransportPreference.WifiDirectBle
                },
            )
        )
        require(preview.relayHandle != identity.relayHandle) { "That invite belongs to this device, you magnificent cryptographic boomerang." }

        val existing = dao.getConversationByPeerHandle(preview.relayHandle)
        val conversationId = existing?.id ?: pairConversationId(identity.relayHandle, preview.relayHandle)
        val safetyCode = cryptoEngine.computeSafetyCode(identity.toIdentityMaterial(), preview.publicBundleBase64)
        val now = System.currentTimeMillis()
        val updatedConversation = applyPeerBundleToConversation(
            existing = existing,
            conversationId = conversationId,
            title = preview.displayName,
            peerHandle = preview.relayHandle,
            publicBundleBase64 = preview.publicBundleBase64,
            now = now,
            defaultSubtitle = "Invite imported · compare safety code before trust",
            lastMessagePreview = "Invite imported. Verify the safety code on both devices before trusting this contact.",
            unreadCount = existing?.unreadCount ?: 0,
            lastContactRequestId = existing?.lastContactRequestId,
        )
        dao.upsertConversation(updatedConversation)

        relayTransport.publishContactRequest(
            RelayContactRequest(
                requestId = UUID.randomUUID().toString(),
                senderHandle = identity.relayHandle,
                recipientHandle = preview.relayHandle,
                senderDisplayName = identity.displayName,
                publicBundleBase64 = identity.publicBundleBase64,
                identityFingerprint = identity.identityFingerprint,
                sentAt = now,
            )
        )

        val statusMessage = if (updatedConversation.trustResetRequired) {
            "Imported ${preview.displayName}, but their safety key changed. Trust was reset. Compare code $safetyCode before believing anything with a padlock icon."
        } else {
            "Imported ${preview.displayName}. Compare safety code $safetyCode on both devices before marking verified."
        }

        return InviteImportResult(
            conversationId = conversationId,
            title = preview.displayName,
            relayHandle = preview.relayHandle,
            safetyCode = safetyCode,
            statusMessage = statusMessage,
        )
    }

    suspend fun safetyCodeForConversation(conversationId: String): String? {
        val identity = dao.getIdentity() ?: return null
        val conversation = dao.getConversation(conversationId) ?: return null
        if (conversation.peerBundleBase64.isBlank()) return null
        return cryptoEngine.computeSafetyCode(identity.toIdentityMaterial(), conversation.peerBundleBase64)
    }

    suspend fun markConversationVerified(conversationId: String): String {
        val conversation = dao.getConversation(conversationId) ?: error("Unknown conversation")
        val safetyCode = safetyCodeForConversation(conversationId) ?: error("Safety code unavailable")
        val resolvedTrust = resolveLocalVerification(conversation)
        if (resolvedTrust.sessionInvalidated) dao.deleteSession(conversationId)
        dao.upsertConversation(
            conversation.copy(
                subtitle = resolvedTrust.subtitle,
                isVerified = resolvedTrust.state.isVerifiedFlag(),
                trustResetRequired = resolvedTrust.state.isTrustResetRequiredFlag(),
                updatedAt = System.currentTimeMillis(),
            )
        )
        return safetyCode
    }

    suspend fun resetConversationTrust(conversationId: String): String {
        val conversation = dao.getConversation(conversationId) ?: error("Unknown conversation")
        val resolvedTrust = resolveLocalTrustReset(conversation)
        if (resolvedTrust.sessionInvalidated) dao.deleteSession(conversationId)
        dao.upsertConversation(
            conversation.copy(
                subtitle = resolvedTrust.subtitle,
                isVerified = resolvedTrust.state.isVerifiedFlag(),
                trustResetRequired = resolvedTrust.state.isTrustResetRequiredFlag(),
                updatedAt = System.currentTimeMillis(),
            )
        )
        return "Trust reset. The fancy encryption graphics do not excuse blind faith."
    }

    suspend fun clearUnread(conversationId: String) {
        val conversation = dao.getConversation(conversationId) ?: return
        val latestRemoteTimestamp = dao.getLatestMessageTimestampBySender(conversationId, MessageSender.RemoteUser.name) ?: 0L
        dao.upsertConversation(
            conversation.copy(
                unreadCount = 0,
                lastReadCursorAt = maxOf(conversation.lastReadCursorAt, latestRemoteTimestamp),
                updatedAt = maxOf(conversation.updatedAt, latestRemoteTimestamp),
            )
        )
        publishReadCursorForConversation(conversationId, latestRemoteTimestamp)
    }

    /**
     * Export the current session state from Rust and persist it to the database.
     * Must be called after every encrypt and decrypt so that counters and chain keys
     * survive app restarts.
     */
    private suspend fun persistSessionState(session: SessionMaterial) {
        try {
            val result = QubeeManager.exportSessionBundle(session.sessionId)
            val updatedBundle = result.payloadOrNull()
            if (updatedBundle != null && updatedBundle.isNotEmpty()) {
                val updatedBase64 = Base64.encodeToString(updatedBundle, Base64.NO_WRAP)
                val existing = dao.getSession(session.conversationId) ?: return
                dao.upsertSession(existing.copy(
                    keyMaterialBase64 = updatedBase64,
                    lastUsedAt = System.currentTimeMillis(),
                ))
            }
        } catch (_: Exception) {
            // Non-fatal: session will work in-memory, but may lose state on restart
        }
    }

    /**
     * Restore all native-backed sessions into Rust's in-memory session map.
     * Must be called after identity restore and before any encrypt/decrypt.
     */
    private suspend fun restoreNativeSessionsFromDb() {
        val sessions = dao.getAllNativeSessions()
        for (entity in sessions) {
            try {
                val bundleBytes = Base64.decode(entity.keyMaterialBase64, Base64.NO_WRAP)
                QubeeManager.restoreSessionBundleOrNull(bundleBytes)
            } catch (_: Exception) {
                // Session data corrupted or incompatible — will be re-created on next use
            }
        }
    }

    suspend fun ensureConversationSession(conversationId: String): SessionMaterial {
        val existing = dao.getSession(conversationId)
        if (existing != null) return existing.toSessionMaterial()

        val identity = dao.getIdentity() ?: error("No local identity present")
        val conversation = dao.getConversation(conversationId) ?: error("Unknown conversation: $conversationId")
        if (conversation.peerBundleBase64.isBlank()) {
            relayTransport.requestPeerBundle(conversation.peerHandle)
            throw IllegalStateException("Peer bundle missing for ${conversation.peerHandle}. Import their invite or wait for relay bundle lookup.")
        }
        require(identity.nativeBacked) {
            "Trusted sessions require a native-backed identity. Preview-shell identities may not create production sessions."
        }
        val session = cryptoEngine.createSession(
            conversationId = conversationId,
            peerHandle = conversation.peerHandle,
            selfPublicBundleBase64 = identity.publicBundleBase64,
            peerPublicBundleBase64 = conversation.peerBundleBase64,
        )
        require(session.nativeBacked) {
            "Trusted sessions require the native hybrid ratchet path."
        }
        hybridDispatcher?.bootstrapPeer(conversation.peerHandle)
        dao.upsertSession(
            SessionEntity(
                conversationId = conversationId,
                sessionId = session.sessionId,
                peerHandle = session.peerHandle,
                keyMaterialBase64 = session.keyMaterialBase64,
                nativeBacked = session.nativeBacked,
                state = session.state,
                bootstrapPayloadBase64 = session.bootstrapPayloadBase64,
                algorithm = session.algorithm,
                createdAt = System.currentTimeMillis(),
                lastUsedAt = System.currentTimeMillis(),
            )
        )
        dao.upsertConversation(
            conversation.copy(
                subtitle = when {
                    conversation.trustResetRequired -> "Safety key changed · verify again before trust"
                    conversation.isVerified && session.nativeBacked -> "Verified · native session active"
                    conversation.isVerified -> "Verified flag set · preview shell session only"
                    session.nativeBacked -> "Invite imported · native session active"
                    else -> "Invite imported · preview shell session only"
                },
                updatedAt = System.currentTimeMillis(),
            )
        )
        return session
    }

    suspend fun sendMessage(conversationId: String, body: String) {
        val trimmed = body.trim()
        if (trimmed.isEmpty()) return

        var session = ensureConversationSession(conversationId)
        val conversation = dao.getConversation(conversationId) ?: return
        val identity = dao.getIdentity() ?: error("No local identity")
        require(identity.nativeBacked) {
            "Trusted messaging requires a native-backed identity."
        }
        require(session.nativeBacked) {
            "Trusted messaging requires a native hybrid session."
        }
        if (!session.bootstrapPayloadBase64.isNullOrBlank()) {
            publishHybridSessionBootstrap(conversation, identity, session)
            session = dao.getSession(conversationId)?.toSessionMaterial() ?: session.copy(bootstrapPayloadBase64 = null)
        }
        val encrypted = cryptoEngine.encryptMessage(session, trimmed)
        persistSessionState(session)
        val timestamp = System.currentTimeMillis()
        val localMessageId = UUID.randomUUID().toString()

        dao.insertMessage(
            MessageEntity(
                id = localMessageId,
                conversationId = conversationId,
                sender = MessageSender.LocalUser.name,
                body = trimmed,
                ciphertextBase64 = encrypted.ciphertextBase64,
                algorithm = encrypted.algorithm,
                timestamp = timestamp,
                deliveryState = DeliveryState.Sending.name,
                isEncrypted = true,
                originDeviceId = identity.deviceId,
            )
        )
        dao.upsertConversation(
            conversation.copy(
                lastMessagePreview = trimmed,
                unreadCount = 0,
                updatedAt = timestamp,
            )
        )

        val outboundEnvelope = RelayEnvelope(
            messageId = localMessageId,
            conversationId = conversationId,
            senderHandle = identity.relayHandle,
            recipientHandle = conversation.peerHandle,
            sessionId = session.sessionId,
            ciphertextBase64 = encrypted.ciphertextBase64,
            algorithm = encrypted.algorithm,
            sentAt = timestamp,
            senderDeviceId = identity.deviceId,
        )
        val deliveryPath = hybridDispatcher?.sendEnvelope(outboundEnvelope)
            ?: if (relayTransport.publish(outboundEnvelope)) DeliveryPath.Relay else DeliveryPath.Failed
        dao.updateMessageState(localMessageId, if (deliveryPath == DeliveryPath.Failed) DeliveryState.Failed.name else DeliveryState.Sent.name)
    }

    private suspend fun publishHybridSessionBootstrap(
        conversation: ConversationEntity,
        identity: IdentityEntity,
        session: SessionMaterial,
    ) {
        val bootstrapPayload = session.bootstrapPayloadBase64 ?: return
        val bootstrapEnvelope = RelayEnvelope(
            messageId = UUID.randomUUID().toString(),
            conversationId = conversation.id,
            senderHandle = identity.relayHandle,
            recipientHandle = conversation.peerHandle,
            sessionId = session.sessionId,
            ciphertextBase64 = bootstrapPayload,
            algorithm = NATIVE_HYBRID_INIT_ALGORITHM,
            sentAt = System.currentTimeMillis(),
            senderDeviceId = identity.deviceId,
        )
        val delivered = hybridDispatcher?.sendEnvelope(bootstrapEnvelope)
            ?: if (relayTransport.publish(bootstrapEnvelope)) DeliveryPath.Relay else DeliveryPath.Failed
        if (delivered == DeliveryPath.Failed) {
            throw IllegalStateException("Failed to publish hybrid session bootstrap for ${conversation.peerHandle}")
        }
        dao.upsertSession(
            SessionEntity(
                conversationId = session.conversationId,
                sessionId = session.sessionId,
                peerHandle = session.peerHandle,
                keyMaterialBase64 = session.keyMaterialBase64,
                nativeBacked = session.nativeBacked,
                state = session.state,
                bootstrapPayloadBase64 = null,
                algorithm = session.algorithm,
                createdAt = System.currentTimeMillis(),
                lastUsedAt = System.currentTimeMillis(),
            )
        )
    }

    private suspend fun applyHistorySync(sync: RelayHistorySync) {
        val normalized = HistoryReconciliation.normalize(sync)
        normalized.contactRequests.forEach { handleIncomingContactRequest(it) }
        normalized.envelopes.forEach { handleIncomingEnvelope(it) }
        normalized.receipts.forEach { handleRelayReceipt(it) }
        normalized.readCursors.forEach { handleReadCursor(it) }
        rememberHistoryCursor(normalized.syncedUntil, normalized.relaySessionId)
    }

    private suspend fun handleIncomingEnvelope(envelope: RelayEnvelope) {
        if (!RelayEnvelopeValidator.isValid(envelope)) {
            rememberHistoryCursor(envelope.sentAt.coerceAtLeast(0L))
            return
        }

        if (dao.getMessage(envelope.messageId) != null) {
            rememberHistoryCursor(envelope.sentAt)
            return
        }

        val conversation = dao.getConversation(envelope.conversationId)
            ?: dao.getConversationByPeerHandle(envelope.senderHandle)
            ?: createConversationForInboundEnvelope(envelope)

        if (envelope.algorithm == NATIVE_HYBRID_INIT_ALGORITHM) {
            handleHybridSessionBootstrapEnvelope(conversation, envelope)
            rememberHistoryCursor(envelope.sentAt)
            return
        }

        val session = runCatching { ensureConversationSession(conversation.id) }.getOrNull()
        val plaintext = if (session != null) {
            runCatching {
                val result = cryptoEngine.decryptMessage(session, EncryptedPayload(envelope.ciphertextBase64, envelope.algorithm))
                persistSessionState(session)
                result
            }.getOrDefault("[decrypt failed]")
        } else {
            relayTransport.requestPeerBundle(conversation.peerHandle)
            "[encrypted message received; waiting for peer bundle/session reconciliation]"
        }

        dao.insertMessage(
            MessageEntity(
                id = envelope.messageId,
                conversationId = conversation.id,
                sender = MessageSender.RemoteUser.name,
                body = plaintext,
                ciphertextBase64 = envelope.ciphertextBase64,
                algorithm = envelope.algorithm,
                timestamp = envelope.sentAt,
                deliveryState = DeliveryState.Delivered.name,
                isEncrypted = true,
                originDeviceId = envelope.senderDeviceId.takeIf { it.isNotBlank() },
            )
        )
        dao.upsertConversation(
            conversation.copy(
                lastMessagePreview = plaintext,
                unreadCount = conversation.unreadCount + 1,
                updatedAt = maxOf(conversation.updatedAt, envelope.sentAt),
            )
        )
        publishDeliveredReceiptForInbound(envelope)
        rememberHistoryCursor(envelope.sentAt)
    }

    private suspend fun handleHybridSessionBootstrapEnvelope(
        conversation: ConversationEntity,
        envelope: RelayEnvelope,
    ) {
        val accepted = cryptoEngine.acceptSessionBootstrap(
            conversationId = conversation.id,
            peerHandle = conversation.peerHandle,
            bootstrapPayloadBase64 = envelope.ciphertextBase64,
        ) ?: run {
            dao.upsertConversation(
                conversation.copy(
                    subtitle = "Hybrid session bootstrap failed · verify peer bundle and retry",
                    updatedAt = maxOf(conversation.updatedAt, envelope.sentAt),
                )
            )
            return
        }

        dao.upsertSession(
            SessionEntity(
                conversationId = conversation.id,
                sessionId = accepted.sessionId,
                peerHandle = accepted.peerHandle,
                keyMaterialBase64 = accepted.keyMaterialBase64,
                nativeBacked = accepted.nativeBacked,
                state = accepted.state,
                bootstrapPayloadBase64 = accepted.bootstrapPayloadBase64,
                algorithm = accepted.algorithm,
                createdAt = System.currentTimeMillis(),
                lastUsedAt = System.currentTimeMillis(),
            )
        )
        dao.upsertConversation(
            conversation.copy(
                subtitle = if (conversation.isVerified) {
                    "Verified · hybrid PQ session active"
                } else {
                    "Hybrid PQ session ready · verify safety code"
                },
                updatedAt = maxOf(conversation.updatedAt, envelope.sentAt),
            )
        )
    }

    private suspend fun handleIncomingContactRequest(request: RelayContactRequest) {
        val localIdentity = dao.getIdentity()
        val existing = dao.getConversationByPeerHandle(request.senderHandle)
        if (existing?.lastContactRequestId == request.requestId) {
            rememberHistoryCursor(request.sentAt)
            return
        }
        val conversationId = existing?.id ?: pairConversationId(localIdentity?.relayHandle ?: "unknown", request.senderHandle)
        val updatedConversation = applyPeerBundleToConversation(
            existing = existing,
            conversationId = conversationId,
            title = existing?.title ?: request.senderDisplayName,
            peerHandle = request.senderHandle,
            publicBundleBase64 = request.publicBundleBase64,
            now = request.sentAt,
            defaultSubtitle = if (existing?.isVerified == true) "Verified contact" else "Incoming contact request · verify safety code",
            lastMessagePreview = "Incoming contact request from ${request.senderDisplayName}.",
            unreadCount = (existing?.unreadCount ?: 0) + 1,
            lastContactRequestId = request.requestId,
        )
        dao.upsertConversation(updatedConversation)
        rememberHistoryCursor(request.sentAt)
    }

    private suspend fun handleRelayReceipt(receipt: RelayReceipt) {
        val localIdentity = dao.getIdentity() ?: return
        val message = dao.getMessage(receipt.messageId) ?: return
        if (message.sender != MessageSender.LocalUser.name || receipt.senderHandle != localIdentity.relayHandle) {
            rememberHistoryCursor(receipt.recordedAt)
            return
        }
        val updated = when (receipt.receiptType.lowercase()) {
            "read" -> message.addReadReceipt(receipt.recipientDeviceId, receipt.recordedAt)
            else -> message.addDeliveredReceipt(receipt.recipientDeviceId, receipt.recordedAt)
        }
        dao.insertMessage(updated)
        rememberHistoryCursor(receipt.recordedAt)
    }

    private suspend fun handleReadCursor(cursor: RelayReadCursor) {
        val identity = dao.getIdentity() ?: return
        val conversation = dao.getConversation(cursor.conversationId) ?: dao.getConversationByPeerHandle(cursor.handle) ?: return

        if (cursor.handle == identity.relayHandle) {
            if (cursor.deviceId != identity.deviceId) {
                dao.upsertConversation(
                    conversation.copy(
                        unreadCount = 0,
                        lastReadCursorAt = maxOf(conversation.lastReadCursorAt, cursor.readThroughTimestamp),
                        updatedAt = maxOf(conversation.updatedAt, cursor.recordedAt),
                    )
                )
            }
            rememberHistoryCursor(cursor.recordedAt)
            return
        }

        val affectedMessages = dao.getMessagesUpToTimestamp(
            conversationId = conversation.id,
            sender = MessageSender.LocalUser.name,
            timestamp = cursor.readThroughTimestamp,
        )
        affectedMessages.forEach { dao.insertMessage(it.addReadReceipt(cursor.deviceId, cursor.recordedAt)) }
        dao.upsertConversation(
            conversation.copy(
                subtitle = if (conversation.trustResetRequired) conversation.subtitle else "Peer read sync across devices active",
                updatedAt = maxOf(conversation.updatedAt, cursor.recordedAt),
            )
        )
        rememberHistoryCursor(cursor.recordedAt)
    }

    private suspend fun createConversationForInboundEnvelope(envelope: RelayEnvelope): ConversationEntity {
        val localHandle = dao.getIdentity()?.relayHandle ?: "unknown"
        val conversation = ConversationEntity(
            id = pairConversationId(localHandle, envelope.senderHandle),
            title = envelope.senderHandle.substringBefore('@'),
            subtitle = "Inbound history restored · verify safety code before trust",
            peerHandle = envelope.senderHandle,
            peerBundleBase64 = "",
            lastMessagePreview = "Encrypted message restored from relay history.",
            unreadCount = 0,
            isVerified = false,
            updatedAt = envelope.sentAt,
            lastContactRequestId = null,
        )
        dao.upsertConversation(conversation)
        return conversation
    }

    private suspend fun updatePeerBundle(peerHandle: String, publicBundleBase64: String?) {
        if (publicBundleBase64.isNullOrBlank()) return
        val existing = dao.getConversationByPeerHandle(peerHandle) ?: return
        val updated = applyPeerBundleToConversation(
            existing = existing,
            conversationId = existing.id,
            title = existing.title,
            peerHandle = peerHandle,
            publicBundleBase64 = publicBundleBase64,
            now = System.currentTimeMillis(),
            defaultSubtitle = existing.subtitle,
            lastMessagePreview = existing.lastMessagePreview,
            unreadCount = existing.unreadCount,
            lastContactRequestId = existing.lastContactRequestId,
        )
        dao.upsertConversation(updated)
    }

    private suspend fun applyPeerBundleToConversation(
        existing: ConversationEntity?,
        conversationId: String,
        title: String,
        peerHandle: String,
        publicBundleBase64: String,
        now: Long,
        defaultSubtitle: String,
        lastMessagePreview: String,
        unreadCount: Int,
        lastContactRequestId: String?,
    ): ConversationEntity {
        val incomingFingerprint = bundleFingerprintFromBase64(publicBundleBase64)
        val trustUpdate = resolvePeerBundleTrust(
            existing = existing,
            incomingFingerprint = incomingFingerprint,
            bundleChanged = existing?.peerBundleBase64 != publicBundleBase64,
            now = now,
            defaultSubtitle = defaultSubtitle,
        )
        if (trustUpdate.sessionInvalidated) dao.deleteSession(conversationId)
        return ConversationEntity(
            id = conversationId,
            title = title,
            subtitle = trustUpdate.subtitle,
            peerHandle = peerHandle,
            peerBundleBase64 = publicBundleBase64,
            lastMessagePreview = lastMessagePreview,
            unreadCount = unreadCount,
            isVerified = trustUpdate.state.isVerifiedFlag(),
            updatedAt = maxOf(existing?.updatedAt ?: 0L, now),
            lastContactRequestId = lastContactRequestId,
            trustResetRequired = trustUpdate.state.isTrustResetRequiredFlag(),
            previousPeerFingerprint = trustUpdate.previousPeerFingerprint,
            lastKeyChangeAt = trustUpdate.lastKeyChangeAt,
            lastReadCursorAt = existing?.lastReadCursorAt ?: 0L,
        )
    }

    private suspend fun publishDeliveredReceiptForInbound(envelope: RelayEnvelope) {
        val identity = dao.getIdentity() ?: return
        val receipt = RelayReceipt(
            receiptId = UUID.randomUUID().toString(),
            messageId = envelope.messageId,
            conversationId = envelope.conversationId,
            senderHandle = envelope.senderHandle,
            recipientHandle = identity.relayHandle,
            recipientDeviceId = identity.deviceId,
            receiptType = "delivered",
            recordedAt = System.currentTimeMillis(),
        )
        val deliveryPath = hybridDispatcher?.sendReceipt(envelope.senderHandle, receipt)
            ?: if (relayTransport.publishReceipt(receipt)) DeliveryPath.Relay else DeliveryPath.Failed
        if (deliveryPath == DeliveryPath.Failed) {
            dao.upsertConversation(
                (dao.getConversation(envelope.conversationId) ?: return).copy(
                    subtitle = "Receipt send failed once; will reconcile on reconnect",
                    updatedAt = System.currentTimeMillis(),
                )
            )
        }
    }

    private suspend fun publishReadCursorForConversation(conversationId: String, readThroughTimestamp: Long) {
        val identity = dao.getIdentity() ?: return
        if (readThroughTimestamp <= 0L) return
        val conversation = dao.getConversation(conversationId) ?: return
        val cursor = RelayReadCursor(
            cursorId = UUID.randomUUID().toString(),
            conversationId = conversationId,
            handle = identity.relayHandle,
            deviceId = identity.deviceId,
            readThroughTimestamp = readThroughTimestamp,
            recordedAt = System.currentTimeMillis(),
        )
        val deliveryPath = hybridDispatcher?.sendReadCursor(conversation.peerHandle, cursor)
            ?: if (relayTransport.publishReadCursor(cursor)) DeliveryPath.Relay else DeliveryPath.Failed
        if (deliveryPath == DeliveryPath.Failed) {
            dao.upsertConversation(
                conversation.copy(
                    subtitle = "Read sync queued; direct peer path unavailable right now",
                    updatedAt = System.currentTimeMillis(),
                )
            )
        }
    }

    private suspend fun rememberHistoryCursor(timestamp: Long, relaySessionId: String? = null) {
        val current = dao.getSyncState() ?: SyncStateEntity(lastHistorySyncAt = 0L, lastRelaySessionId = "")
        dao.upsertSyncState(
            current.copy(
                lastHistorySyncAt = maxOf(current.lastHistorySyncAt, timestamp),
                lastRelaySessionId = relaySessionId ?: current.lastRelaySessionId,
            )
        )
    }

    private suspend fun connectRelay(identity: IdentityEntity) {
        if (!identity.nativeBacked) {
            relayTransport.disconnect()
            return
        }
        relayTransport.connect(
            RelayConfig(
                relayUrl = BuildConfig.DEFAULT_RELAY_URL,
                localHandle = identity.relayHandle,
                deviceId = identity.deviceId,
                displayName = identity.displayName,
            ),
            object : RelayAuthenticator {
                override suspend fun createHello(config: RelayConfig): RelayHello = RelayHello(
                    handle = identity.relayHandle,
                    deviceId = identity.deviceId,
                    displayName = identity.displayName,
                    publicBundleBase64 = identity.publicBundleBase64,
                    identityFingerprint = identity.identityFingerprint,
                )

                override suspend fun signChallenge(challenge: String, relaySessionId: String): RelayAuthProof? =
                    cryptoEngine.signRelayChallenge(identity.toIdentityMaterial(), challenge, relaySessionId)?.let { signature ->
                        RelayAuthProof(
                            handle = identity.relayHandle,
                            relaySessionId = relaySessionId,
                            challenge = challenge,
                            publicBundleBase64 = identity.publicBundleBase64,
                            identityFingerprint = identity.identityFingerprint,
                            signatureBase64 = signature,
                        )
                    }
            }
        )
    }
}

private fun IdentityMaterial.toEntity(): IdentityEntity = IdentityEntity(
    displayName = displayName,
    deviceLabel = deviceLabel,
    identityFingerprint = identityFingerprint,
    publicBundleBase64 = publicBundleBase64,
    identityBundleBase64 = identityBundleBase64,
    relayHandle = relayHandle,
    deviceId = deviceId,
    nativeBacked = nativeBacked,
    createdAt = System.currentTimeMillis(),
)

private fun IdentityEntity.toUserProfile(): UserProfile = UserProfile(
    displayName = displayName,
    deviceLabel = deviceLabel,
    identityFingerprint = identityFingerprint,
    publicBundleBase64 = publicBundleBase64,
    relayHandle = relayHandle,
    deviceId = deviceId,
)

private fun IdentityEntity.toIdentityMaterial(): IdentityMaterial = IdentityMaterial(
    displayName = displayName,
    deviceLabel = deviceLabel,
    identityFingerprint = identityFingerprint,
    publicBundleBase64 = publicBundleBase64,
    identityBundleBase64 = identityBundleBase64,
    relayHandle = relayHandle,
    deviceId = deviceId,
    nativeBacked = nativeBacked,
)

private fun ConversationEntity.toSummary(): ConversationSummary = ConversationSummary(
    id = id,
    title = title,
    subtitle = subtitle,
    peerHandle = peerHandle,
    lastMessagePreview = lastMessagePreview,
    unreadCount = unreadCount,
    isVerified = isVerified,
    updatedAt = updatedAt,
    trustResetRequired = trustResetRequired,
    lastKeyChangeAt = lastKeyChangeAt,
    lastReadCursorAt = lastReadCursorAt,
)

private fun MessageEntity.toChatMessage(): ChatMessage = ChatMessage(
    id = id,
    conversationId = conversationId,
    sender = MessageSender.valueOf(sender),
    body = body,
    timestamp = timestamp,
    deliveryState = DeliveryState.valueOf(deliveryState),
    isEncrypted = isEncrypted,
    originDeviceId = originDeviceId,
    deliveredToDeviceCount = deliveredToDeviceCount,
    readByDeviceCount = readByDeviceCount,
    lastReceiptAt = lastReceiptAt,
)

private fun pairConversationId(localHandle: String, remoteHandle: String): String {
    val pair = listOf(localHandle, remoteHandle).sorted().joinToString("|")
    return UUID.nameUUIDFromBytes(pair.toByteArray()).toString()
}

private fun SessionEntity.toSessionMaterial(): SessionMaterial = SessionMaterial(
    conversationId = conversationId,
    sessionId = sessionId,
    peerHandle = peerHandle,
    keyMaterialBase64 = keyMaterialBase64,
    nativeBacked = nativeBacked,
    state = state,
    bootstrapPayloadBase64 = bootstrapPayloadBase64,
    algorithm = algorithm,
)

private fun MessageEntity.addDeliveredReceipt(deviceId: String, recordedAt: Long): MessageEntity {
    val devices = deliveredToDevicesJson.toDeviceSet().apply { add(deviceId) }
    return copy(
        deliveryState = if (DeliveryState.valueOf(deliveryState) == DeliveryState.Read) DeliveryState.Read.name else DeliveryState.Delivered.name,
        deliveredToDeviceCount = devices.size,
        deliveredToDevicesJson = devices.toJsonArrayString(),
        lastReceiptAt = maxOf(lastReceiptAt, recordedAt),
    )
}

private fun MessageEntity.addReadReceipt(deviceId: String, recordedAt: Long): MessageEntity {
    val delivered = deliveredToDevicesJson.toDeviceSet().apply { add(deviceId) }
    val readers = readByDevicesJson.toDeviceSet().apply { add(deviceId) }
    return copy(
        deliveryState = DeliveryState.Read.name,
        deliveredToDeviceCount = delivered.size,
        deliveredToDevicesJson = delivered.toJsonArrayString(),
        readByDeviceCount = readers.size,
        readByDevicesJson = readers.toJsonArrayString(),
        lastReceiptAt = maxOf(lastReceiptAt, recordedAt),
    )
}

private fun String.toDeviceSet(): MutableSet<String> = runCatching {
    val array = JSONArray(this)
    buildSet {
        for (index in 0 until array.length()) add(array.getString(index))
    }.toMutableSet()
}.getOrDefault(mutableSetOf())

private fun Set<String>.toJsonArrayString(): String = JSONArray(this.toList()).toString()
