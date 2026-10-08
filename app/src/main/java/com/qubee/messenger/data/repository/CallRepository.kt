package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Bridges the native Rust CallManager (via [QubeeManager] JNI) to the
 * app. Call signaling rides the encrypted 1:1 session — [MessageService]
 * (the NetworkCallback) sends outbound frames and feeds inbound ones to
 * the native call state machine, and drives this repository's lifecycle
 * hooks.
 *
 * The current call is held in a durable [StateFlow] so a late-arriving
 * collector (the call UI, which subscribes after startup) always sees
 * the present state rather than missing a one-shot event.
 *
 * The media root passed to [initiateCall] / [acceptCall] is the 32-byte
 * secret both endpoints derive from their shared 1:1 session.
 */
@Singleton
class CallRepository @Inject constructor(
    private val qubeeManager: QubeeManager,
) {
    /** The single in-flight call this device is party to, if any. */
    sealed interface CallUiState {
        /** No call in progress. */
        object Idle : CallUiState

        /** A remote party is ringing us; awaiting accept/reject. */
        data class Incoming(
            val callIdHex: String,
            val peerIdHex: String,
            val callType: Int,
        ) : CallUiState

        /** A call we're in — initiated by us or accepted. */
        data class Active(
            val callIdHex: String,
            val peerIdHex: String,
            val callType: Int,
        ) : CallUiState
    }

    private val _state = MutableStateFlow<CallUiState>(CallUiState.Idle)
    val state: StateFlow<CallUiState> = _state.asStateFlow()

    /**
     * True only when this APK was built with `-PqubeeCalling=true` and the
     * loaded `libqubee_crypto.so` actually exported the calling symbols.
     * The default release leaves both false so the UI cannot imply a call
     * button that the native library does not contain.
     */
    private val _callingAvailable = MutableStateFlow(false)
    val callingAvailable: StateFlow<Boolean> = _callingAvailable.asStateFlow()

    /** Bring up the native call subsystem for the active identity. */
    suspend fun start(): Boolean {
        if (!com.qubee.messenger.BuildConfig.CALLING_NATIVE_ENABLED) {
            _callingAvailable.value = false
            return false
        }
        val started = qubeeManager.startCalling()
        _callingAvailable.value = started
        return started
    }

    /**
     * Place a call. The media root is minted natively and shipped in
     * the encrypted invitation. Returns the new call id (hex) or null.
     */
    suspend fun initiateCall(peerIdHex: String, isVideo: Boolean): String? {
        val peer = identityHexOrNull(peerIdHex) ?: return null
        val callType = if (isVideo) 1 else 0
        val callIdHex = qubeeManager.initiateCall(peer, callType) ?: return null
        _state.value = CallUiState.Active(callIdHex, peer, callType)
        return callIdHex
    }

    /**
     * A session peer is a 32-byte identity id, hex-encoded. A phone
     * number, email, or other dial string is not an address.
     */
    private fun identityHexOrNull(value: String): String? {
        if (value.length != 64) return null
        if (value.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) return null
        return value
    }

    /** Accept the currently-ringing call (media root came from the invite). */
    suspend fun acceptCall(callIdHex: String, peerIdHex: String): Boolean {
        val peer = identityHexOrNull(peerIdHex) ?: return false
        // Snapshot the ringing state before suspending: a terminal
        // lifecycle callback (hang-up, timeout) can land while
        // acceptCall() awaits, and we must not clobber it.
        val callType = (_state.value as? CallUiState.Incoming)
            ?.takeIf { it.callIdHex == callIdHex }
            ?.callType
            ?: return false
        val accepted = qubeeManager.acceptCall(callIdHex, peer)
        if (accepted) {
            // Only transition if this call is still the one ringing.
            val current = _state.value
            if (current is CallUiState.Incoming && current.callIdHex == callIdHex) {
                _state.value = CallUiState.Active(callIdHex, peer, callType)
            }
        }
        return accepted
    }

    /** End (or leave) a call; always returns to idle locally. */
    suspend fun endCall(callIdHex: String, peerIdHex: String): Boolean {
        val ended = qubeeManager.endCall(callIdHex, peerIdHex)
        _state.value = CallUiState.Idle
        return ended
    }

    /** Reject a ringing call — the same teardown as ending it. */
    suspend fun rejectCall(callIdHex: String, peerIdHex: String): Boolean =
        endCall(callIdHex, peerIdHex)

    /** Toggle local mute; returns the new muted state, or null on error. */
    suspend fun toggleMute(callIdHex: String, peerIdHex: String): Boolean? =
        qubeeManager.toggleMute(callIdHex, peerIdHex)

    /** Toggle local video; returns the new enabled state, or null on error. */
    suspend fun toggleVideo(callIdHex: String, peerIdHex: String): Boolean? =
        qubeeManager.toggleVideo(callIdHex, peerIdHex)

    /** From the NetworkCallback: a remote invite is ringing. */
    fun onIncoming(callIdHex: String, callerIdHex: String, callType: Int) {
        // Ignore a second invite while already busy with a call.
        if (_state.value is CallUiState.Idle) {
            _state.value = CallUiState.Incoming(callIdHex, callerIdHex, callType)
        }
    }

    /** From the NetworkCallback: a native lifecycle token for a call. */
    fun onStateChanged(callIdHex: String, stateToken: String) {
        val current = _state.value
        val concernsCurrent = when (current) {
            is CallUiState.Incoming -> current.callIdHex == callIdHex
            is CallUiState.Active -> current.callIdHex == callIdHex
            CallUiState.Idle -> false
        }
        if (concernsCurrent && isTerminal(stateToken)) {
            _state.value = CallUiState.Idle
        }
    }

    private fun isTerminal(token: String): Boolean {
        val t = token.lowercase()
        return t.startsWith("ended") ||
            t.startsWith("left") ||
            t.startsWith("rejected") ||
            t.startsWith("timedout") ||
            t.startsWith("cancelled") ||
            t.startsWith("error")
    }
}
