package com.qubee.messenger.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.background.RelaySyncWorker
import com.qubee.messenger.data.MessengerRepository
import com.qubee.messenger.data.QubeeServiceLocator
import com.qubee.messenger.model.ChatMessage
import com.qubee.messenger.model.ConnectivityDiagnostics
import com.qubee.messenger.model.LinkedDeviceRecord
import com.qubee.messenger.model.ConversationSummary
import com.qubee.messenger.model.InviteShareBundle
import com.qubee.messenger.model.NativeAvailability
import com.qubee.messenger.model.NativeBridgeStatus
import com.qubee.messenger.model.RelayConnectionState
import com.qubee.messenger.model.RelayStatus
import com.qubee.messenger.model.TrustDetails
import com.qubee.messenger.model.UserProfile
import com.qubee.messenger.model.VaultLockState
import com.qubee.messenger.network.p2p.LocalBootstrapStatus
import com.qubee.messenger.network.p2p.WebRtcPathState
import com.qubee.messenger.network.p2p.WebRtcPathStatus
import com.qubee.messenger.model.VaultStatus
import com.qubee.messenger.security.KillSwitch
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch

data class AppUiState(
    val vaultStatus: VaultStatus = VaultStatus(),
    val onboardingComplete: Boolean = false,
    val conversations: List<ConversationSummary> = emptyList(),
    val activeConversation: ConversationSummary? = null,
    val messages: List<ChatMessage> = emptyList(),
    val activeTrustDetails: TrustDetails? = null,
    val nativeStatus: NativeBridgeStatus = NativeBridgeStatus(
        availability = NativeAvailability.Unavailable,
        details = "Native hybrid crypto is not ready yet.",
    ),
    val relayStatus: RelayStatus = RelayStatus(
        state = RelayConnectionState.Disconnected,
        details = "Relay disconnected.",
        relayUrl = "bootstrap://locked",
    ),
    val profile: UserProfile? = null,
    val inviteShare: InviteShareBundle? = null,
    val activeSafetyCode: String? = null,
    val inviteNotice: String? = null,
    val lastImportedConversationId: String? = null,
    val linkedDevices: List<LinkedDeviceRecord> = emptyList(),
    val connectivityDiagnostics: ConnectivityDiagnostics = ConnectivityDiagnostics(
        localBootstrapDetails = "Local bootstrap idle.",
        localBootstrapReady = false,
        webRtcDetails = "WebRTC data path idle.",
        webRtcReady = false,
        openChannelCount = 0,
        knownConversationCount = 0,
        secureMessagingReady = false,
        securityPosture = "Native hybrid cryptography is unavailable. Preview flows may render, but they are not trustworthy secure messaging.",
    ),
)

@OptIn(ExperimentalCoroutinesApi::class)
class AppViewModel(application: Application) : AndroidViewModel(application) {
    private val services = QubeeServiceLocator.from(application)
    private var repository: MessengerRepository? = null
    private var repositoryCollectorsBound = false

    private val vaultStatusState = MutableStateFlow(
        VaultStatus(
            state = VaultLockState.Locked,
            details = if (services.hasExistingVault()) {
                "Encrypted vault detected. Authenticate to open SQLCipher and restore native identity state."
            } else {
                "No vault initialized yet. Authenticate once so Qubee can create the keystore-wrapped SQLCipher passphrase."
            },
            hasExistingVault = services.hasExistingVault(),
        )
    )
    private val profileState = MutableStateFlow<UserProfile?>(null)
    private val conversationsState = MutableStateFlow<List<ConversationSummary>>(emptyList())
    private val activeConversationId = MutableStateFlow<String?>(null)
    private val inviteShareState = MutableStateFlow<InviteShareBundle?>(null)
    private val safetyCodeState = MutableStateFlow<String?>(null)
    private val inviteNoticeState = MutableStateFlow<String?>(null)
    private val importedConversationState = MutableStateFlow<String?>(null)
    private val linkedDevicesState = MutableStateFlow<List<LinkedDeviceRecord>>(emptyList())
    private val webRtcStatusState = MutableStateFlow(WebRtcPathStatus())
    private val localBootstrapStatusState = MutableStateFlow(LocalBootstrapStatus())
    private val nativeStatusState = MutableStateFlow(services.cryptoEngine.status())
    private val relayStatusState = MutableStateFlow(
        RelayStatus(
            state = RelayConnectionState.Disconnected,
            details = "Transport stack idle until the vault is unlocked.",
            relayUrl = "bootstrap://locked",
        )
    )

    var uiState by mutableStateOf(AppUiState())
        private set

    init {
        viewModelScope.launch {
            combine(
                vaultStatusState,
                profileState,
                conversationsState,
                activeConversationId.flatMapLatest { id ->
                    val repo = repository
                    if (id == null || repo == null) flowOf(null) else repo.conversationFlow(id)
                },
                activeConversationId.flatMapLatest { id ->
                    val repo = repository
                    if (id == null || repo == null) flowOf(emptyList()) else repo.messagesFlow(id)
                },
                activeConversationId.flatMapLatest { id ->
                    val repo = repository
                    if (id == null || repo == null) flowOf(null) else repo.trustDetailsFlow(id)
                },
                nativeStatusState,
                relayStatusState,
                inviteShareState,
                safetyCodeState,
                inviteNoticeState,
                importedConversationState,
                linkedDevicesState,
                webRtcStatusState,
                localBootstrapStatusState,
            ) { vaultStatus, profile, conversations, activeConversation, messages, trustDetails, nativeStatus, relayStatus, inviteShare, safetyCode, inviteNotice, importedConversationId, linkedDevices, webRtcStatus, localBootstrapStatus ->
                AppUiState(
                    vaultStatus = vaultStatus,
                    onboardingComplete = profile != null,
                    conversations = conversations,
                    activeConversation = activeConversation,
                    messages = messages,
                    activeTrustDetails = trustDetails,
                    nativeStatus = nativeStatus,
                    relayStatus = relayStatus,
                    profile = profile,
                    inviteShare = inviteShare,
                    activeSafetyCode = safetyCode,
                    inviteNotice = inviteNotice,
                    lastImportedConversationId = importedConversationId,
                    linkedDevices = linkedDevices,
                    connectivityDiagnostics = ConnectivityDiagnostics(
                        localBootstrapDetails = localBootstrapStatus.details,
                        localBootstrapReady = localBootstrapStatus.ready,
                        webRtcDetails = webRtcStatus.details,
                        webRtcReady = webRtcStatus.state == WebRtcPathState.Ready,
                        openChannelCount = webRtcStatus.openChannelCount,
                        knownConversationCount = conversations.size,
                        secureMessagingReady = nativeStatus.availability == NativeAvailability.Ready,
                        securityPosture = if (nativeStatus.availability == NativeAvailability.Ready) {
                            "Native hybrid ML-KEM session bootstrap is available and relay authentication can use PQ-capable signatures."
                        } else {
                            "Fallback shell mode is preview-only and not a post-quantum secure transport path. Do not treat it as a trusted messenger state."
                        },
                    ),
                )
            }.collect { uiState = it }
        }
    }

    fun beginUnlock() {
        vaultStatusState.value = vaultStatusState.value.copy(
            state = VaultLockState.Unlocking,
            details = "Waiting for biometric or device-credential approval.",
        )
    }

    fun onUnlockCancelledOrFailed(message: String) {
        vaultStatusState.value = vaultStatusState.value.copy(
            state = VaultLockState.Error,
            details = message,
        )
    }

    fun onUnlockAuthenticated() {
        viewModelScope.launch {
            runCatching {
                val unlockedRepository = services.unlockRepository()
                repository = unlockedRepository
                bindRepository(unlockedRepository)
                RelaySyncWorker.schedule(getApplication())
                unlockedRepository.initialize()
                inviteShareState.value = unlockedRepository.exportInviteShare()
                vaultStatusState.value = VaultStatus(
                    state = VaultLockState.Unlocked,
                    details = if (services.hasExistingVault()) {
                        "Vault unlocked. SQLCipher is open and native identity restoration has been attempted."
                    } else {
                        "Vault initialized and unlocked. You can now create the local identity."
                    },
                    hasExistingVault = services.hasExistingVault(),
                )
            }.onFailure {
                vaultStatusState.value = VaultStatus(
                    state = VaultLockState.Error,
                    details = it.message ?: "Unlock failed while opening the secure vault.",
                    hasExistingVault = services.hasExistingVault(),
                )
            }
        }
    }

    private fun bindRepository(repo: MessengerRepository) {
        if (repositoryCollectorsBound) return
        repositoryCollectorsBound = true
        viewModelScope.launch {
            repo.profileFlow.collect {
                profileState.value = it
                inviteShareState.value = if (it == null) null else repo.exportInviteShare()
                linkedDevicesState.value = buildLinkedDevices(it, conversationsState.value, activeTrustDetails = uiState.activeTrustDetails)
            }
        }
        viewModelScope.launch {
            repo.conversationsFlow.collect { list ->
                conversationsState.value = list
                linkedDevicesState.value = buildLinkedDevices(profileState.value, list, activeTrustDetails = uiState.activeTrustDetails)
            }
        }
        viewModelScope.launch { repo.nativeStatus.collect { nativeStatusState.value = it } }
        viewModelScope.launch { repo.relayStatus.collect { relayStatusState.value = it } }
        viewModelScope.launch { services.webRtcEnvelopeTransport.status.collect { webRtcStatusState.value = it } }
        viewModelScope.launch { services.localBootstrapTransport.status.collect { localBootstrapStatusState.value = it } }
    }

    fun completeOnboarding(displayName: String) {
        val repo = repository ?: run {
            inviteNoticeState.value = "Unlock the secure vault before creating an identity."
            return
        }
        viewModelScope.launch {
            repo.bootstrapIdentity(displayName)
            inviteShareState.value = repo.exportInviteShare()
            inviteNoticeState.value = "Identity created. Your invite payload is ready for QR/share bootstrap."
        }
    }

    fun openConversation(conversationId: String) {
        val repo = repository ?: run {
            inviteNoticeState.value = "Unlock the secure vault before opening conversations."
            return
        }
        activeConversationId.value = conversationId
        viewModelScope.launch {
            repo.clearUnread(conversationId)
            val result = runCatching { repo.ensureConversationSession(conversationId) }
            safetyCodeState.value = repo.safetyCodeForConversation(conversationId)
            inviteNoticeState.value = result.exceptionOrNull()?.message
        }
    }

    fun sendMessage(body: String) {
        val repo = repository ?: run {
            inviteNoticeState.value = "Unlock the secure vault before sending messages."
            return
        }
        val conversationId = activeConversationId.value ?: return
        viewModelScope.launch {
            runCatching { repo.sendMessage(conversationId, body) }
                .onFailure { inviteNoticeState.value = it.message }
        }
    }

    fun importInvite(payload: String) {
        val repo = repository ?: run {
            inviteNoticeState.value = "Unlock the secure vault before importing invites."
            return
        }
        viewModelScope.launch {
            runCatching { repo.importInvitePayload(payload) }
                .onSuccess {
                    inviteNoticeState.value = it.statusMessage
                    safetyCodeState.value = it.safetyCode
                    importedConversationState.value = it.conversationId
                }
                .onFailure { inviteNoticeState.value = it.message ?: "Invite import failed" }
        }
    }

    fun verifyActiveConversation() {
        val repo = repository ?: return
        val conversationId = activeConversationId.value ?: return
        viewModelScope.launch {
            runCatching { repo.markConversationVerified(conversationId) }
                .onSuccess {
                    safetyCodeState.value = it
                    inviteNoticeState.value = "Safety code $it verified. Contact marked trusted."
                }
                .onFailure { inviteNoticeState.value = it.message ?: "Verification failed" }
        }
    }

    fun resetActiveConversationTrust() {
        val repo = repository ?: return
        val conversationId = activeConversationId.value ?: return
        viewModelScope.launch {
            runCatching { repo.resetConversationTrust(conversationId) }
                .onSuccess {
                    inviteNoticeState.value = it
                    safetyCodeState.value = repo.safetyCodeForConversation(conversationId)
                }
                .onFailure { inviteNoticeState.value = it.message ?: "Trust reset failed" }
        }
    }

    fun consumeImportedConversationNavigation() {
        importedConversationState.value = null
    }


    fun nukeDevice() {
        viewModelScope.launch {
            runCatching { KillSwitch.execute(getApplication()) }
            repository = null
            repositoryCollectorsBound = false
            activeConversationId.value = null
            profileState.value = null
            conversationsState.value = emptyList()
            inviteShareState.value = null
            safetyCodeState.value = null
            importedConversationState.value = null
            nativeStatusState.value = services.cryptoEngine.status()
            relayStatusState.value = RelayStatus(
                state = RelayConnectionState.Disconnected,
                details = "Local state wiped. Restart the app before trusting anything that claims to still be alive.",
                relayUrl = "bootstrap://wiped",
            )
            vaultStatusState.value = VaultStatus(
                state = VaultLockState.Locked,
                details = "Device state wiped. Restart the app to initialize a fresh vault.",
                hasExistingVault = services.hasExistingVault(),
            )
            inviteNoticeState.value = "Local device state destroyed. Restart Qubee before reinitializing the vault."
        }
    }

    fun notifyInviteShared(kind: String) {
        inviteNoticeState.value = when (kind) {
            "copy" -> "Invite payload copied. Now send it through a channel that does not make your threat model cry."
            "share" -> "Invite payload handed to Android sharing. Choose the least ridiculous transport available."
            else -> "Invite action completed."
        }
    }

    fun dismissNotice() {
        inviteNoticeState.value = null
    }


    private fun buildLinkedDevices(
        profile: UserProfile?,
        conversations: List<ConversationSummary>,
        activeTrustDetails: TrustDetails?,
    ): List<LinkedDeviceRecord> {
        val devices = mutableListOf<LinkedDeviceRecord>()
        if (profile != null) {
            devices += LinkedDeviceRecord(
                id = profile.deviceId,
                title = profile.deviceLabel,
                subtitle = "${profile.displayName} · current device",
                trustLabel = "trusted",
                isCurrentDevice = true,
                isTrusted = true,
            )
        }
        if (activeTrustDetails != null) {
            devices += LinkedDeviceRecord(
                id = "${activeTrustDetails.peerHandle}:${activeTrustDetails.localDeviceId}",
                title = "Peer session view",
                subtitle = "${activeTrustDetails.peerHandle} · ${activeTrustDetails.sessionState}",
                trustLabel = if (activeTrustDetails.isVerified) "verified" else "review",
                isCurrentDevice = false,
                isTrusted = activeTrustDetails.isVerified,
            )
        }
        conversations.forEach { conversation ->
            devices += LinkedDeviceRecord(
                id = conversation.id,
                title = conversation.title,
                subtitle = "${conversation.peerHandle} · ${conversation.updatedAtLabel}",
                trustLabel = if (conversation.isVerified) "verified" else if (conversation.trustResetRequired) "key changed" else "unverified",
                isCurrentDevice = false,
                isTrusted = conversation.isVerified && !conversation.trustResetRequired,
            )
        }
        return devices.distinctBy { it.id }
    }
}
