package com.qubee.messenger.ui.call

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.repository.CallRepository
import com.qubee.messenger.data.repository.CallRepository.CallUiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [CallOverlay] from the durable call state in [CallRepository].
 *
 * `reject` and `hangUp` are fully wired (they only need the call id and
 * peer). `accept` and the in-call mute/video toggles depend on two
 * pieces still tracked in issue #67 — deriving the per-call media root
 * from the 1:1 session, and native mute/video toggles — so they update
 * local UI state and log rather than fabricate anything.
 */
@HiltViewModel
class CallViewModel @Inject constructor(
    private val callRepository: CallRepository,
) : ViewModel() {

    val state: StateFlow<CallUiState> = callRepository.state

    private val _muted = MutableStateFlow(false)
    val muted: StateFlow<Boolean> = _muted.asStateFlow()

    private val _videoOn = MutableStateFlow(false)
    val videoOn: StateFlow<Boolean> = _videoOn.asStateFlow()

    /**
     * Accept the ringing call. The media root was provisioned from the
     * caller's encrypted invitation, so no key is passed here.
     */
    fun accept() {
        val incoming = state.value as? CallUiState.Incoming ?: return
        viewModelScope.launch {
            callRepository.acceptCall(incoming.callIdHex, incoming.peerIdHex)
        }
    }

    /** Reject the ringing call. */
    fun reject() {
        val incoming = state.value as? CallUiState.Incoming ?: return
        viewModelScope.launch {
            callRepository.rejectCall(incoming.callIdHex, incoming.peerIdHex)
        }
    }

    /** Hang up (or leave) the active call. */
    fun hangUp() {
        val call = state.value
        val (callIdHex, peerIdHex) = when (call) {
            is CallUiState.Active -> call.callIdHex to call.peerIdHex
            is CallUiState.Incoming -> call.callIdHex to call.peerIdHex
            CallUiState.Idle -> return
        }
        viewModelScope.launch { callRepository.endCall(callIdHex, peerIdHex) }
    }

    /** Toggle mute on the active call; reflects the native result. */
    fun toggleMute() {
        val active = state.value as? CallUiState.Active ?: return
        viewModelScope.launch {
            callRepository.toggleMute(active.callIdHex, active.peerIdHex)?.let { _muted.value = it }
        }
    }

    /** Toggle video on the active call; reflects the native result. */
    fun toggleVideo() {
        val active = state.value as? CallUiState.Active ?: return
        viewModelScope.launch {
            callRepository.toggleVideo(active.callIdHex, active.peerIdHex)?.let { _videoOn.value = it }
        }
    }
}
