package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    private val operations = Mutex()
    private val lifecycleLock = Any()
    private var lifecycleRevision = 0L

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
    suspend fun initiateCall(peerIdHex: String, isVideo: Boolean): String? = operations.withLock {
        if (!_callingAvailable.value || isVideo) return null
        val peer = identityHexOrNull(peerIdHex) ?: return null
        val revision = synchronized(lifecycleLock) {
            if (_state.value != CallUiState.Idle) return null
            lifecycleRevision
        }
        val callIdHex = qubeeManager.initiateCall(peer, 0) ?: return null
        val published = synchronized(lifecycleLock) {
            revision == lifecycleRevision && _callingAvailable.value &&
                _state.compareAndSet(CallUiState.Idle, CallUiState.Active(callIdHex, peer, 0))
        }
        if (!published) {
            qubeeManager.endCall(callIdHex, peer)
            return null
        }
        callIdHex
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
    suspend fun acceptCall(callIdHex: String, peerIdHex: String): Boolean = operations.withLock {
        if (!_callingAvailable.value) return false
        val peer = identityHexOrNull(peerIdHex) ?: return false
        val (incoming, revision) = synchronized(lifecycleLock) {
            val incoming = (_state.value as? CallUiState.Incoming)
                ?.takeIf { it.callIdHex == callIdHex && it.peerIdHex == peer && it.callType == 0 }
                ?: return false
            incoming to lifecycleRevision
        }
        val accepted = qubeeManager.acceptCall(callIdHex, peer)
        if (!accepted) return false
        val published = synchronized(lifecycleLock) {
            revision == lifecycleRevision && _callingAvailable.value &&
                _state.compareAndSet(incoming, CallUiState.Active(callIdHex, peer, 0))
        }
        if (!published) {
            qubeeManager.endCall(callIdHex, peer)
        }
        published
    }

    /** End (or leave) the matching call, without clearing a newer lifecycle. */
    suspend fun endCall(callIdHex: String, peerIdHex: String): Boolean = operations.withLock {
        val (current, revision) = synchronized(lifecycleLock) {
            val current = _state.value
            if (!current.matches(callIdHex, peerIdHex)) return false
            current to lifecycleRevision
        }
        val ended = qubeeManager.endCall(callIdHex, peerIdHex)
        synchronized(lifecycleLock) {
            if (revision == lifecycleRevision && _state.compareAndSet(current, CallUiState.Idle)) {
                lifecycleRevision++
            }
        }
        ended
    }

    /** Reject a ringing call — the same teardown as ending it. */
    suspend fun rejectCall(callIdHex: String, peerIdHex: String): Boolean =
        endCall(callIdHex, peerIdHex)

    /** Toggle local mute; returns the new muted state, or null on error. */
    suspend fun toggleMute(callIdHex: String, peerIdHex: String): Boolean? = operations.withLock {
        val (current, revision) = synchronized(lifecycleLock) {
            val current = _state.value as? CallUiState.Active ?: return null
            if (!current.matches(callIdHex, peerIdHex)) return null
            current to lifecycleRevision
        }
        val muted = qubeeManager.toggleMute(callIdHex, peerIdHex)
        synchronized(lifecycleLock) {
            muted.takeIf { revision == lifecycleRevision && _state.value == current }
        }
    }

    /** Video remains unavailable until the voice-only hardware validation is complete. */
    @Suppress("UNUSED_PARAMETER")
    suspend fun toggleVideo(callIdHex: String, peerIdHex: String): Boolean? =
        null

    /** From the NetworkCallback: a remote invite is ringing. */
    fun onIncoming(callIdHex: String, callerIdHex: String, callType: Int) {
        if (!_callingAvailable.value || callType != 0 || identityHexOrNull(callerIdHex) == null) return
        synchronized(lifecycleLock) {
            if (_state.compareAndSet(CallUiState.Idle, CallUiState.Incoming(callIdHex, callerIdHex, callType))) {
                lifecycleRevision++
            }
        }
    }

    /** From the NetworkCallback: a native lifecycle token for a call. */
    fun onStateChanged(callIdHex: String, stateToken: String) {
        if (!isTerminal(stateToken)) return
        synchronized(lifecycleLock) {
            val current = _state.value
            val concernsCurrent = when (current) {
                is CallUiState.Incoming -> current.callIdHex == callIdHex
                is CallUiState.Active -> current.callIdHex == callIdHex
                CallUiState.Idle -> false
            }
            // A newly initiated call can terminate before JNI returns its id.
            if (current == CallUiState.Idle || concernsCurrent) {
                lifecycleRevision++
            }
            if (concernsCurrent) {
                _state.compareAndSet(current, CallUiState.Idle)
            }
        }
    }

    private fun CallUiState.matches(callIdHex: String, peerIdHex: String): Boolean = when (this) {
        is CallUiState.Incoming -> this.callIdHex == callIdHex && this.peerIdHex == peerIdHex
        is CallUiState.Active -> this.callIdHex == callIdHex && this.peerIdHex == peerIdHex
        CallUiState.Idle -> false
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
