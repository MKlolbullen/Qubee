package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Bridges the native Rust CallManager (via [QubeeManager] JNI) to the
 * app. Call signaling rides the encrypted 1:1 session — [MessageService]
 * (the NetworkCallback) sends outbound frames and feeds inbound ones to
 * the native call state machine, and publishes lifecycle events here for
 * the call UI to observe.
 *
 * The media root passed to [initiateCall] / [acceptCall] is the 32-byte
 * secret both endpoints derive from their shared 1:1 session.
 */
@Singleton
class CallRepository @Inject constructor(
    private val qubeeManager: QubeeManager,
) {
    /** A call lifecycle event surfaced from the native layer. */
    sealed interface CallEvent {
        data class Incoming(
            val callIdHex: String,
            val callerIdHex: String,
            val callType: Int,
        ) : CallEvent

        data class StateChanged(val callIdHex: String, val state: String) : CallEvent
    }

    private val _events = MutableSharedFlow<CallEvent>(extraBufferCapacity = 16)
    val events: SharedFlow<CallEvent> = _events.asSharedFlow()

    /** Bring up the native call subsystem for the active identity. */
    suspend fun start(): Boolean = qubeeManager.startCalling()

    /** Place a call. Returns the new call id (hex) or null. */
    suspend fun initiateCall(
        participantIdHex: String,
        isVideo: Boolean,
        mediaRoot: ByteArray,
    ): String? =
        qubeeManager.initiateCall(participantIdHex, if (isVideo) 1 else 0, mediaRoot)

    suspend fun acceptCall(
        callIdHex: String,
        participantIdHex: String,
        mediaRoot: ByteArray,
    ): Boolean = qubeeManager.acceptCall(callIdHex, participantIdHex, mediaRoot)

    suspend fun endCall(callIdHex: String, participantIdHex: String): Boolean =
        qubeeManager.endCall(callIdHex, participantIdHex)

    /** Publish an inbound-call event from the NetworkCallback thread. */
    fun publishIncoming(callIdHex: String, callerIdHex: String, callType: Int) {
        _events.tryEmit(CallEvent.Incoming(callIdHex, callerIdHex, callType))
    }

    /** Publish a call lifecycle state change from the NetworkCallback thread. */
    fun publishStateChanged(callIdHex: String, state: String) {
        _events.tryEmit(CallEvent.StateChanged(callIdHex, state))
    }
}
