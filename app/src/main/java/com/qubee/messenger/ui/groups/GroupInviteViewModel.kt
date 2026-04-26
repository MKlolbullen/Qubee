package com.qubee.messenger.ui.groups

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.repository.GroupRepository
import com.qubee.messenger.groups.AcceptInviteResult
import com.qubee.messenger.groups.GroupInvite
import com.qubee.messenger.groups.GroupInviteRequest
import com.qubee.messenger.groups.CreatedInvite
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Drives the group create-and-invite UI. Keeps state for the most recent
 * generated invite link and the most recently scanned/pasted invite.
 *
 * Pure UI state holder — actual peer/group bookkeeping lives in
 * [com.qubee.messenger.data.repository.GroupRepository] and the Rust core.
 */
@HiltViewModel
class GroupInviteViewModel @Inject constructor(
    private val groupRepository: GroupRepository,
) : ViewModel() {

    val maxMembers: Int = groupRepository.maxMembers

    private val _state = MutableStateFlow(InviteUiState())
    val state: StateFlow<InviteUiState> = _state.asStateFlow()

    /**
     * Create a brand new group AND mint an invite link for it in one
     * shot. This is the path the "New group" UI takes — most users
     * never want to create a group without an invite, so we collapse
     * the two JNI calls into a single ViewModel action.
     *
     * `ttlSeconds` defaults to 24h and accepts null for "no expiry".
     */
    fun createGroupAndInvite(
        name: String,
        ttlSeconds: Long? = DEFAULT_INVITE_TTL_SECONDS,
    ) {
        if (name.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(isWorking = true, error = null)
            val created = groupRepository.createGroup(name.trim())
            if (created == null) {
                _state.value = _state.value.copy(
                    isWorking = false,
                    error = "Could not create group (is the identity onboarded?)",
                )
                return@launch
            }
            val expiresAt = ttlSeconds?.let { System.currentTimeMillis() / 1000L + it } ?: -1L
            val invite = groupRepository.createInvite(created.groupIdHex, expiresAt, maxUses = -1)
            _state.value = if (invite != null) {
                _state.value.copy(
                    isWorking = false,
                    groupName = invite.groupName,
                    generatedLink = invite.link,
                    createdInvite = invite,
                )
            } else {
                _state.value.copy(
                    isWorking = false,
                    error = "Group created, but invite link generation failed",
                )
            }
        }
    }

    /**
     * Build a `qubee://invite/...` link for an existing group. The
     * caller is expected to have already created the group on the Rust
     * side and passed its identifiers in.
     */
    fun generateInvite(
        groupIdHex: String,
        groupName: String,
        inviterIdHex: String,
        inviterName: String,
        invitationCode: String,
        ttlSeconds: Long? = DEFAULT_INVITE_TTL_SECONDS,
    ) {
        val expiresAt = ttlSeconds?.let { System.currentTimeMillis() / 1000L + it }
        val request = GroupInviteRequest(
            groupIdHex = groupIdHex,
            groupName = groupName,
            inviterIdHex = inviterIdHex,
            inviterName = inviterName,
            invitationCode = invitationCode,
            expiresAt = expiresAt,
        )
        viewModelScope.launch {
            _state.value = _state.value.copy(isWorking = true, error = null)
            val link = groupRepository.buildInviteLink(request)
            _state.value = if (link != null) {
                _state.value.copy(isWorking = false, generatedLink = link, groupName = groupName)
            } else {
                _state.value.copy(isWorking = false, error = "Could not build invite link")
            }
        }
    }

    /**
     * Decode either a scanned QR or a pasted deep link into a structured
     * [GroupInvite]. Updates [InviteUiState.scannedInvite] (and remembers
     * the original link in [InviteUiState.scannedLink]) with the result.
     */
    fun decodeScannedLink(link: String) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isWorking = true, error = null, scannedLink = link)
            val invite = groupRepository.parseInviteLink(link)
            _state.value = if (invite != null) {
                _state.value.copy(isWorking = false, scannedInvite = invite)
            } else {
                _state.value.copy(
                    isWorking = false,
                    error = "Invalid Qubee invite link",
                    scannedLink = null,
                )
            }
        }
    }

    /**
     * Persist acceptance of the invite the user just inspected and
     * publish a signed `RequestJoin` over the network. The UI gets
     * back the structured outcome so it can tell the user whether
     * the handshake actually went out or whether they need to try
     * again once they're on a network.
     */
    fun acceptInvite() {
        val link = _state.value.scannedLink ?: return
        viewModelScope.launch {
            _state.value = _state.value.copy(isWorking = true, error = null)
            val accepted = groupRepository.acceptInvite(link)
            _state.value = if (accepted != null) {
                _state.value.copy(
                    isWorking = false,
                    accepted = true,
                    acceptanceResult = accepted,
                )
            } else {
                _state.value.copy(
                    isWorking = false,
                    error = "Could not record invite acceptance",
                )
            }
        }
    }

    fun clearScanned() {
        _state.value = _state.value.copy(
            scannedInvite = null,
            scannedLink = null,
            accepted = false,
            acceptanceResult = null,
        )
    }

    /**
     * Acknowledge that the UI has surfaced the latest error (e.g. via
     * a Snackbar). Without this the same error would re-trigger on
     * every recomposition that observes `state`.
     */
    fun consumeError() {
        if (_state.value.error != null) {
            _state.value = _state.value.copy(error = null)
        }
    }

    companion object {
        const val DEFAULT_INVITE_TTL_SECONDS: Long = 24 * 60 * 60
    }
}

data class InviteUiState(
    val isWorking: Boolean = false,
    val groupName: String? = null,
    val generatedLink: String? = null,
    /** Set when the user just created a brand new group via the UI. */
    val createdInvite: CreatedInvite? = null,
    val scannedInvite: GroupInvite? = null,
    val scannedLink: String? = null,
    /** The invite has been recorded in the encrypted group keystore. */
    val accepted: Boolean = false,
    /** Network publication outcome — null until accept is invoked. */
    val acceptanceResult: AcceptInviteResult? = null,
    val error: String? = null,
)
