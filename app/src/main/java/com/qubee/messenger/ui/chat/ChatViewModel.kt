package com.qubee.messenger.ui.chat

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.Message
import com.qubee.messenger.data.model.MessageStatus
import com.qubee.messenger.data.model.MessageType
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.MessageRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

// Real chat surface ViewModel. Wires `MessageRepository`
// (Flow<List<MessageWithSender>>) and `ContactRepository` into the
// surface that `ChatScreen.kt` consumes (`uiState.details`,
// `uiState.securityState`, `events`, plus the action methods
// `requestSecureCall`, `requestContactVerification`,
// `changeDisappearingTimer`, `resetSecureSession`, `clearChat`).
@HiltViewModel
class ChatViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val messageRepository: MessageRepository,
    private val contactRepository: ContactRepository,
    private val conversationRepository: ConversationRepository,
    private val groupRepository: com.qubee.messenger.data.repository.GroupRepository,
    private val qubeeManager: QubeeManager,
) : ViewModel() {

    private val contactId: String = savedStateHandle["contactId"] ?: ""

    private val _uiState = MutableStateFlow(
        ChatUiState(
            contactName = contactId.take(8),
            details = ConversationDetailsUi.placeholder(),
        ),
    )
    val uiState: StateFlow<ChatUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<ChatUiEvent>(extraBufferCapacity = 4)
    val events: SharedFlow<ChatUiEvent> = _events.asSharedFlow()

    private var conversationId: String = ""

    // Resolved at init time from `QubeeManager.getMyIdentityId()`. Null
    // until onboarding completes; sendMessage falls back to the
    // contact id in that window so the row still persists.
    private var selfSenderId: String? = null

    init {
        viewModelScope.launch {
            // Resolve the conversation row + contact metadata first
            // so subsequent sendMessage calls have a target to write
            // to, then start streaming messages.
            conversationId = conversationRepository.getOrCreateConversationId(contactId)
            val conversation = conversationRepository.getConversationById(conversationId)
            // For groups the row's `name` is authoritative (set by
            // GroupInviteViewModel at create / accept). For 1:1 the
            // row's `name` is empty, so we fall back to the
            // contact's display name and then to a hex prefix.
            val isGroup =
                conversation?.type == com.qubee.messenger.data.model.ConversationType.GROUP
            val contact = contactRepository.getContactById(contactId)
            val name = when {
                isGroup -> conversation?.name?.takeIf { it.isNotBlank() } ?: "Group"
                else -> contact?.displayName?.takeIf { it.isNotBlank() } ?: contactId.take(8)
            }

            // Honour persisted trust state: a contact whose
            // `trustLevel` is `TrustLevel.VERIFIED` (set by a
            // previous successful `confirmContactVerification`) opens
            // straight into the verified security state. Without
            // this, the badge resets to Unverified on every restart.
            val isAlreadyVerified = contact?.trustLevel == TrustLevel.VERIFIED
            val initialDetails = ConversationDetailsUi.placeholder().copy(
                fingerprint = (contact?.identityKey?.toFingerprint() ?: "Not available"),
                isVerified = isAlreadyVerified,
                verificationLabel = when {
                    isAlreadyVerified -> "Verified"
                    contact == null -> "Unknown"
                    else -> "Unverified"
                },
            )
            // Load our own fingerprint once so the verify dialog can
            // render it as a QR for the peer to scan. Best-effort —
            // null on JNI miss / pre-onboarding state, dialog hides
            // the my-QR section in that case.
            val myFp = runCatching { qubeeManager.getMyFingerprint() }.getOrNull()
            val myId = runCatching { qubeeManager.getMyIdentityIdHex() }.getOrNull()
            selfSenderId = runCatching { qubeeManager.getMyIdentityId() }.getOrNull()

            _uiState.value = _uiState.value.copy(
                contactName = name,
                details = initialDetails,
                securityState = if (isAlreadyVerified) {
                    ConversationSecurityState.Verified
                } else {
                    ConversationSecurityState.Unverified
                },
                myFingerprint = myFp,
                myIdentityIdHex = myId,
                isGroup = isGroup,
            )

            messageRepository
                .getMessagesForConversation(conversationId)
                .map { rows -> rows.map { it.toUi() } }
                .collect { uiMessages ->
                    _uiState.value = _uiState.value.copy(messages = uiMessages)
                }
        }
    }

    // ---- Send / actions -------------------------------------------

    fun sendMessage(text: String) {
        val payload = text.trim()
        if (payload.isEmpty() || conversationId.isEmpty()) return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            val message = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = selfSenderId ?: SELF_SENDER_ID_FALLBACK,
                content = payload,
                contentType = MessageType.TEXT,
                timestamp = now,
                status = MessageStatus.SENDING,
                isFromMe = true,
            )
            messageRepository.saveMessage(message)

            // Encrypt via the Rust JNI bridge. The session id is the
            // hex-encoded GroupId — same value as conversationId per
            // ConversationRepository.getOrCreateConversationId.
            val encrypted = runCatching { qubeeManager.encryptMessage(conversationId, payload) }
                .getOrNull()
            if (encrypted == null) {
                messageRepository.updateMessageStatus(message.id, MessageStatus.FAILED)
                _events.emit(
                    ChatUiEvent.Notice(
                        "Encrypt failed — peer may not have accepted the group invite yet",
                    ),
                )
                return@launch
            }

            // Publish via libp2p. The "peer id" passed to
            // sendP2PMessage today is whatever the caller hands in;
            // we forward the application-level contactId (the same
            // string ChatFragment received as a nav arg). The Rust
            // side resolves it; if libp2p doesn't have a route the
            // command is queued, not actually delivered. Status =
            // SENT here means "encrypted bytes left this device",
            // not "peer ack". Real delivery confirmation is a
            // post-alpha hook.
            val sendOk = runCatching {
                qubeeManager.sendP2PMessage(contactId, encrypted.toBytes())
            }.getOrDefault(false)
            val newStatus = if (sendOk) MessageStatus.SENT else MessageStatus.FAILED
            messageRepository.updateMessageStatus(message.id, newStatus)
            if (!sendOk) {
                _events.emit(ChatUiEvent.Notice("P2P send failed"))
            }
        }
    }

    /**
     * Queue a file attachment. Placeholder — writes a [Message] of
     * [MessageType.FILE] with empty content, so the row appears in
     * the chat. Real selection / encryption / upload lands later.
     */
    fun onAttachFile() {
        if (conversationId.isEmpty()) return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            val msg = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = selfSenderId ?: SELF_SENDER_ID_FALLBACK,
                content = "",
                contentType = MessageType.FILE,
                timestamp = now,
                status = MessageStatus.SENDING,
                isFromMe = true,
            )
            messageRepository.saveMessage(msg)
            _events.emit(ChatUiEvent.Notice("File attachment queued (encryption not yet implemented)"))
        }
    }

    /**
     * Queue a photo. Placeholder — writes a [Message] of
     * [MessageType.IMAGE] with empty content. Camera integration +
     * encryption land later.
     */
    fun onTakePhoto() {
        if (conversationId.isEmpty()) return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            val msg = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = selfSenderId ?: SELF_SENDER_ID_FALLBACK,
                content = "",
                contentType = MessageType.IMAGE,
                timestamp = now,
                status = MessageStatus.SENDING,
                isFromMe = true,
            )
            messageRepository.saveMessage(msg)
            _events.emit(ChatUiEvent.Notice("Photo queued (camera integration not yet implemented)"))
        }
    }

    /**
     * Queue an audio note. Placeholder — recording / encryption /
     * playback land later.
     */
    fun onRecordAudio() {
        if (conversationId.isEmpty()) return
        viewModelScope.launch {
            val now = System.currentTimeMillis()
            val msg = Message(
                id = UUID.randomUUID().toString(),
                conversationId = conversationId,
                senderId = selfSenderId ?: SELF_SENDER_ID_FALLBACK,
                content = "",
                contentType = MessageType.AUDIO,
                timestamp = now,
                status = MessageStatus.SENDING,
                isFromMe = true,
            )
            messageRepository.saveMessage(msg)
            _events.emit(ChatUiEvent.Notice("Voice note queued (recording not yet implemented)"))
        }
    }

    /**
     * Secure calling — gated on the Rust `calling` feature flag and
     * a yet-unbuilt signalling layer. Surfaces a notice for now.
     */
    fun requestSecureCall() {
        notice("Secure calling lands post-alpha (calling feature flag)")
    }

    /**
     * Smoke-call the JNI verify bridge to confirm the symbol resolves
     * and the byte plumbing round-trips. Does NOT claim
     * [ConversationSecurityState.Verified] — the real OOB compare
     * gesture (display the contact's fingerprint, user types/scans
     * the expected value, bridge returns true/false) needs UI
     * affordances that haven't landed. Calling here means a missing
     * `nativeVerifyIdentityKey` symbol surfaces at this known site
     * with a recoverable error, not at first user-driven verify.
     *
     * Both Rust- and Kotlin-side fingerprint formats live in
     * different shapes today (Rust hashes `(classical_pub || pq_pub)`
     * with BLAKE3 and groups as `"AABB CCDD …"`; Kotlin's
     * [toFingerprint] takes the first 8 raw bytes with dashes), so
     * the smoke call deliberately uses an empty expected payload —
     * the bridge will return false but the JNI invocation completes,
     * which is what we're checking.
     */
    fun requestContactVerification() {
        if (conversationId.isEmpty()) {
            notice("No conversation to verify")
            return
        }
        viewModelScope.launch {
            val contact = contactRepository.getContactById(contactId)
            val peerIdKey = contact?.identityKey
            if (peerIdKey == null) {
                _events.emit(ChatUiEvent.Notice("Peer identity not stored — cannot verify yet"))
                return@launch
            }
            // Compute the canonical fingerprint via the Rust JNI
            // bridge. The Kotlin-side `toFingerprint` extension
            // formats the first 8 raw bytes with dashes and does
            // NOT match what `IdentityKey::fingerprint()` produces
            // — using it for OOB compare would have peers staring at
            // different strings on their two devices and concluding
            // the verification failed when it didn't.
            val canonicalFingerprint = runCatching {
                qubeeManager.computeFingerprint(peerIdKey)
            }.getOrNull()
            if (canonicalFingerprint == null) {
                _events.emit(
                    ChatUiEvent.Notice("Verification bridge unreachable or peer identity malformed"),
                )
                return@launch
            }
            // SAS is a nice-to-have; the fingerprint compare path
            // works without it. Failures here just hide the SAS
            // section of the dialog.
            val sasCode = runCatching {
                qubeeManager.generateSASForContact(peerIdKey)
            }.getOrNull()
            val updatedDetails = _uiState.value.details.copy(
                fingerprint = canonicalFingerprint,
                verificationLabel = "Compare with peer",
                isVerified = false,
            )
            _uiState.value = _uiState.value.copy(
                details = updatedDetails,
                pendingVerification = true,
                pendingSas = sasCode,
            )
            _events.emit(
                ChatUiEvent.Notice("Compare $canonicalFingerprint with the contact's device"),
            )
        }
    }

    /**
     * Close the OOB-verification dialog without making any changes.
     * Called from the dialog's Cancel button + system back press.
     */
    fun dismissContactVerification() {
        _uiState.value = _uiState.value.copy(pendingVerification = false, pendingSas = null)
    }

    /**
     * SAS-compare confirmation. Called when both peers have
     * independently looked at the same SAS code on their devices
     * and agreed it matches. Both devices compute the same code
     * (Rust orders the byte buffers lexicographically before the
     * BLAKE3 hash), so a "yes they match" claim from the user is
     * itself the trust ceremony — no `verifyIdentityKey` round-
     * trip needed.
     *
     * Persists `TrustLevel.VERIFIED` +
     * `ContactVerificationStatus.VERIFIED_ONCE` so a restart
     * honours the trust bump, flips uiState.securityState to
     * Verified, and dismisses the dialog. Symmetric end state with
     * the fingerprint path — they're two routes to the same row
     * mutation.
     */
    fun confirmSasMatch() {
        if (conversationId.isEmpty()) {
            notice("No conversation to verify")
            return
        }
        viewModelScope.launch {
            contactRepository.updateTrustLevel(contactId, TrustLevel.VERIFIED)
            contactRepository.updateVerificationStatus(
                contactId,
                ContactVerificationStatus.VERIFIED_ONCE,
            )
            val current = _uiState.value
            _uiState.value = current.copy(
                details = current.details.copy(
                    isVerified = true,
                    verificationLabel = "Verified",
                ),
                securityState = ConversationSecurityState.Verified,
                pendingVerification = false,
                pendingSas = null,
            )
            _events.emit(ChatUiEvent.Notice("Contact verified via SAS"))
        }
    }

    /**
     * User-driven OOB compare confirmation. Called once the user has
     * read the peer's fingerprint (or SAS code) on their *other*
     * device and entered/scanned it locally. Routes through
     * `qubeeManager.verifyIdentityKey` for the actual cryptographic
     * comparison; on success, persists the trust bump to
     * `ContactRepository` (so a restart keeps the verified state),
     * flips the UI to [ConversationSecurityState.Verified], and
     * dismisses the verification dialog.
     *
     * `expectedFingerprint` is matched case- and space-insensitively
     * against `IdentityKey::fingerprint()` on the Rust side, so the
     * user can paste a `"AABB CCDD EEFF GGHH"` string verbatim or
     * type it in lower-case without separators — both work.
     *
     * On mismatch the dialog stays open so the user can retry
     * without re-navigating to it.
     */
    fun confirmContactVerification(expectedFingerprint: String) {
        if (conversationId.isEmpty()) {
            notice("No conversation to verify")
            return
        }
        viewModelScope.launch {
            val contact = contactRepository.getContactById(contactId)
            val peerIdKey = contact?.identityKey
            if (peerIdKey == null) {
                _events.emit(ChatUiEvent.Notice("Peer identity not stored — cannot verify yet"))
                return@launch
            }
            val expectedBytes = expectedFingerprint.trim().toByteArray()
            if (expectedBytes.isEmpty()) {
                _events.emit(ChatUiEvent.Notice("Enter the fingerprint shown on the contact's device"))
                return@launch
            }
            val matches = runCatching {
                qubeeManager.verifyIdentityKey(contactId, peerIdKey, expectedBytes)
            }.getOrDefault(false)
            if (!matches) {
                _events.emit(
                    ChatUiEvent.Notice(
                        "Fingerprints don't match — verification failed. Compare both devices again.",
                    ),
                )
                return@launch
            }
            // Persist so a restart honours the trust bump.
            contactRepository.updateTrustLevel(contactId, TrustLevel.VERIFIED)
            contactRepository.updateVerificationStatus(
                contactId,
                ContactVerificationStatus.VERIFIED_ONCE,
            )
            val current = _uiState.value
            _uiState.value = current.copy(
                details = current.details.copy(
                    isVerified = true,
                    verificationLabel = "Verified",
                ),
                securityState = ConversationSecurityState.Verified,
                pendingVerification = false,
                pendingSas = null,
            )
            _events.emit(ChatUiEvent.Notice("Contact verified"))
        }
    }

    /**
     * Cycle the disappearing-message timer label through Off → 30s →
     * 5m → Off. Persistence + the actual timer-driven cleanup land
     * later — for now this only updates the UI state.
     */
    fun changeDisappearingTimer() {
        viewModelScope.launch {
            val current = _uiState.value
            val nextLabel = when (current.details.disappearingTimerLabel) {
                "Off" -> "30s"
                "30s" -> "5m"
                else -> "Off"
            }
            _uiState.value = current.copy(
                details = current.details.copy(disappearingTimerLabel = nextLabel),
            )
            _events.emit(ChatUiEvent.Notice("Disappearing timer set to $nextLabel"))
        }
    }

    /**
     * Reset the local identity via [QubeeManager.resetIdentity] and
     * re-initialise the core. On success, the conversation drops
     * back to [ConversationSecurityState.Unverified].
     */
    fun resetSecureSession() {
        viewModelScope.launch {
            val ok = runCatching { qubeeManager.resetIdentity() }
                .getOrElse { err ->
                    _events.emit(
                        ChatUiEvent.Notice("Reset bridge unreachable: ${err.message ?: "unknown error"}"),
                    )
                    return@launch
                }
            if (!ok) {
                _events.emit(ChatUiEvent.Notice("Failed to reset secure session"))
                return@launch
            }
            val initOk = runCatching { qubeeManager.initialize() }.getOrDefault(false)
            if (!initOk) {
                _events.emit(ChatUiEvent.Notice("Session reset but reinitialisation failed"))
                return@launch
            }
            val current = _uiState.value
            _uiState.value = current.copy(
                details = current.details.copy(
                    isVerified = false,
                    verificationLabel = "Unverified",
                ),
                securityState = ConversationSecurityState.Unverified,
            )
            _events.emit(ChatUiEvent.Notice("Secure session reset and reinitialised"))
        }
    }

    /**
     * Load the current group's member roster from the Rust core.
     * Called when the user opens the Group Details sheet — keeps
     * the call lazy so the JNI round-trip only happens when
     * actually needed.
     *
     * On null (group not yet known to the Rust core, e.g. invite
     * accepted but JoinAccepted handshake hasn't landed yet) we
     * surface an empty list, which the UI renders as an explicit
     * "no members yet" state rather than an indefinite spinner.
     */
    fun loadGroupMembers() {
        if (!_uiState.value.isGroup || conversationId.isEmpty()) return
        viewModelScope.launch {
            val members = groupRepository.listGroupMembers(conversationId) ?: emptyList()
            _uiState.value = _uiState.value.copy(groupMembers = members)
        }
    }

    /**
     * Mint a fresh invite link for the current group and emit a
     * `ShareLink` event so the host launches the system share
     * sheet. Owner-only Rust-side; non-owner callers see a
     * "Failed to mint invite" notice (the JNI call returns null,
     * which we map to the same UX as a transient JNI failure).
     *
     * Default TTL is 24h via `groupRepository.createInvite`'s
     * `expiresAtSeconds` parameter — passing -1 here would mean
     * "no expiry" but that's not the right default for a
     * member-add gesture on a live chat. Hardcoded to 24h for
     * now; configurable in a follow-up.
     */
    fun addMember() {
        if (!_uiState.value.isGroup || conversationId.isEmpty()) return
        viewModelScope.launch {
            val expiresAt = System.currentTimeMillis() / 1000L + 24L * 60L * 60L
            val invite = runCatching {
                groupRepository.createInvite(
                    groupIdHex = conversationId,
                    expiresAtSeconds = expiresAt,
                    maxUses = 1,
                )
            }.getOrNull()
            val link = invite?.link
            if (link == null) {
                _events.emit(ChatUiEvent.Notice("Failed to mint invite (owner only?)"))
                return@launch
            }
            _events.emit(
                ChatUiEvent.ShareLink(
                    link = link,
                    title = "Share Qubee group invite",
                ),
            )
        }
    }

    /**
     * Remove a member from the current group. Owner / Admin only
     * Rust-side; callers without permission see "Failed to remove
     * member" via the null-mapped JNI return.
     *
     * The Rust core publishes a `KeyRotation` after a successful
     * removal so the remaining members converge on a fresh group
     * key the kicked member can no longer decrypt with — the
     * removed member stays subscribed to the gossipsub topic but
     * sees only the encrypted bytes from this point.
     */
    fun removeMember(memberIdHex: String) {
        if (!_uiState.value.isGroup || conversationId.isEmpty()) return
        viewModelScope.launch {
            val ok = runCatching {
                groupRepository.removeMember(conversationId, memberIdHex, "removed by admin")
            }.getOrNull() != null
            if (ok) {
                _events.emit(ChatUiEvent.Notice("Member removed"))
                // Refresh roster so the UI drops the row.
                loadGroupMembers()
            } else {
                _events.emit(ChatUiEvent.Notice("Failed to remove member"))
            }
        }
    }

    /**
     * Promote (or demote) a member to a new role. Owner-only Rust-
     * side; non-owner callers see a "Failed to update role" notice
     * via the null-mapped JNI return.
     *
     * Caller passes one of the small fixed vocabulary the JNI
     * accepts — `"Admin"`, `"Moderator"`, `"Member"`, `"Observer"`
     * (case-insensitive). Owner is excluded from the UI: rotating
     * ownership requires its own confirmed transfer flow, which
     * this batch doesn't ship.
     *
     * On success the Rust core publishes a signed `RoleChange`
     * frame so other members converge on the same membership view;
     * we follow up with `loadGroupMembers` so the local roster row
     * picks up the new role label without waiting for a sheet
     * dismiss-and-reopen.
     */
    fun promoteMember(memberIdHex: String, newRole: String) {
        if (!_uiState.value.isGroup || conversationId.isEmpty()) return
        viewModelScope.launch {
            val ok = runCatching {
                groupRepository.promoteMember(conversationId, memberIdHex, newRole)
            }.getOrNull() != null
            if (ok) {
                _events.emit(ChatUiEvent.Notice("Role updated to $newRole"))
                loadGroupMembers()
            } else {
                _events.emit(ChatUiEvent.Notice("Failed to update role (owner only?)"))
            }
        }
    }

    /**
     * Leave the current group. Routes through the existing
     * `removeMember` JNI export — the Rust side accepts
     * "remove yourself" the same way it accepts an owner removing
     * someone else, just with `member_id = self_id`. Triggers a
     * local key rotation so the user no longer holds the
     * post-rotation key; remaining members get a `KeyRotation`
     * broadcast and converge on the fresh key.
     *
     * The local Conversation row stays in place after a leave —
     * the user can still scroll back through the message history
     * even though they can no longer post or decrypt new
     * messages. A future "archive after leave" follow-up would
     * collapse the row from the active inbox.
     */
    fun leaveGroup() {
        if (!_uiState.value.isGroup || conversationId.isEmpty()) return
        val myId = _uiState.value.myIdentityIdHex
        if (myId.isNullOrBlank()) {
            notice("Cannot leave: local identity not loaded")
            return
        }
        viewModelScope.launch {
            val ok = runCatching {
                groupRepository.removeMember(conversationId, myId, "leaving")
            }.getOrNull() != null
            if (ok) {
                _events.emit(ChatUiEvent.Notice("You left the group"))
            } else {
                _events.emit(ChatUiEvent.Notice("Failed to leave group"))
            }
        }
    }

    fun clearChat() {
        if (conversationId.isEmpty()) return
        viewModelScope.launch {
            messageRepository.deleteAllMessagesForConversation(conversationId)
            _events.emit(ChatUiEvent.Notice("Chat cleared on this device"))
        }
    }

    private fun notice(message: String) {
        viewModelScope.launch { _events.emit(ChatUiEvent.Notice(message)) }
    }

    private fun com.qubee.messenger.data.model.MessageWithSender.toUi(): UiMessage {
        val msg = this.message
        return UiMessage(
            id = msg.id,
            text = msg.content,
            isFromMe = msg.isFromMe,
            timestamp = msg.timestamp,
            type = msg.contentType.toUiType(),
            status = msg.status.toUiStatus(msg.isFromMe),
        )
    }

    private companion object {
        // Used only when the JNI accessor for `getMyIdentityId()`
        // returns null (pre-onboarding state, JNI link miss). In
        // steady-state, every persisted message carries the locally-
        // resolved 64-char hex identity id — same shape as
        // `nativeInspectEnvelopeSender` returns for inbound rows.
        const val SELF_SENDER_ID_FALLBACK: String = "self"
    }
}

data class ChatUiState(
    val contactName: String = "",
    val messages: List<UiMessage> = emptyList(),
    val details: ConversationDetailsUi = ConversationDetailsUi.placeholder(),
    val securityState: ConversationSecurityState = ConversationSecurityState.Unverified,
    /// True while the OOB-verification dialog is open. Flipped on by
    /// `requestContactVerification`, off by `confirmContactVerification`
    /// (fingerprint match) or `confirmSasMatch` (SAS match) on
    /// success, or `dismissContactVerification` on user cancel.
    /// On verify-failure (fingerprint mismatch) it stays true so the
    /// dialog stays open for retry.
    val pendingVerification: Boolean = false,
    /// SAS code for the pending verification, computed alongside the
    /// fingerprint when `requestContactVerification` runs. `null`
    /// when SAS isn't available (no active identity, JNI failure,
    /// etc.) — the dialog renders the fingerprint half but hides
    /// the SAS section in that case.
    val pendingSas: String? = null,
    /// The locally-active identity's own fingerprint, in the
    /// `"AABB CCDD EEFF GGHH"` shape. Loaded once at
    /// `ChatViewModel.init` time. Rendered as a QR code in the
    /// verify dialog so the peer can scan it and verify *us*. Null
    /// until onboarding completes / the JNI getter resolves.
    val myFingerprint: String? = null,
    /// True when the current conversation row is a group rather than
    /// a 1:1 chat. Read at `init` time from `Conversation.type` and
    /// then static for the lifetime of the screen — switching from
    /// DIRECT to GROUP would require a fresh navigation.
    val isGroup: Boolean = false,
    /// Lazily-loaded roster shown in the Group Details sheet.
    /// Populated by `loadGroupMembers()` when the user opens the
    /// sheet; `null` means "not loaded yet" (the UI shows a
    /// spinner), an empty list means "Rust core has no group at
    /// this id" (the UI shows the empty-state copy).
    val groupMembers: List<com.qubee.messenger.groups.GroupMemberInfo>? = null,
    /// The locally-active identity id, hex-encoded. Loaded once at
    /// init alongside `myFingerprint`. The Group Details sheet
    /// matches this against `GroupMemberInfo.identityIdHex` to put
    /// a "You" badge on the row representing the local user.
    val myIdentityIdHex: String? = null,
)

data class ConversationDetailsUi(
    val fingerprint: String,
    val isVerified: Boolean,
    val verificationLabel: String,
    val sessionLabel: String,
    val sessionNote: String,
    val disappearingTimerLabel: String,
    val mediaCount: Int,
    val fileCount: Int,
    val audioCount: Int,
) {
    companion object {
        fun placeholder() = ConversationDetailsUi(
            fingerprint = "Loading…",
            isVerified = false,
            verificationLabel = "Checking",
            sessionLabel = "Loading session",
            sessionNote = "Inspecting local session state.",
            disappearingTimerLabel = "Off",
            mediaCount = 0,
            fileCount = 0,
            audioCount = 0,
        )
    }
}

data class UiMessage(
    val id: String = "",
    val text: String = "",
    val isFromMe: Boolean = false,
    val timestamp: Long = 0L,
    val type: UiMessageType = UiMessageType.TEXT,
    val status: MessageDeliveryState = MessageDeliveryState.Sent,
)

enum class UiMessageType { TEXT, IMAGE, FILE, AUDIO }

sealed class ChatUiEvent {
    data class Notice(val message: String) : ChatUiEvent()
    /// Asks the host (ChatFragment / ChatScreen) to launch the
    /// system share sheet with the given text. Used by the
    /// "Add member" action — fresh group invite link is minted
    /// in the ViewModel, but the share-intent has to be fired
    /// from a Context the Composable owns.
    data class ShareLink(val link: String, val title: String) : ChatUiEvent()
}

private fun MessageType.toUiType(): UiMessageType = when (this) {
    MessageType.TEXT -> UiMessageType.TEXT
    MessageType.IMAGE, MessageType.VIDEO -> UiMessageType.IMAGE
    MessageType.FILE -> UiMessageType.FILE
    MessageType.AUDIO, MessageType.VOICE -> UiMessageType.AUDIO
}

private fun MessageStatus.toUiStatus(isFromMe: Boolean): MessageDeliveryState = when (this) {
    MessageStatus.SENDING -> MessageDeliveryState.Queued
    MessageStatus.SENT -> MessageDeliveryState.Sent
    MessageStatus.DELIVERED -> MessageDeliveryState.Delivered
    MessageStatus.READ -> MessageDeliveryState.Delivered
    MessageStatus.FAILED -> MessageDeliveryState.Failed
}

private fun ByteArray.toFingerprint(): String = take(8)
    .joinToString("-") { byte -> "%02X".format(byte) }
    .ifBlank { "Not available" }
