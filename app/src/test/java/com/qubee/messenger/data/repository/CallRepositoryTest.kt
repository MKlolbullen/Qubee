package com.qubee.messenger.data.repository

import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.CallRepository.CallUiState
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyNoInteractions
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED
import kotlin.coroutines.resume

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class CallRepositoryTest {
    private val manager = mock(QubeeManager::class.java)
    private val repository = CallRepository(manager)
    private val peer = "ab".repeat(32)
    private val call = "first-call"
    private val replacement = "second-call"

    @Suppress("UNCHECKED_CAST")
    private fun enableCalling() {
        val field = CallRepository::class.java.getDeclaredField("_callingAvailable")
        field.isAccessible = true
        (field.get(repository) as MutableStateFlow<Boolean>).value = true
    }

    private suspend fun activate() {
        enableCalling()
        `when`(manager.initiateCall(peer, 0)).thenReturn(call)
        assertEquals(call, repository.initiateCall(peer, false))
    }

    @Test
    fun unavailable_calling_never_reaches_native_or_publishes_an_invite() = runTest {
        assertNull(repository.initiateCall(peer, false))
        repository.onIncoming(call, peer, 0)
        assertFalse(repository.acceptCall(call, peer))
        assertEquals(CallUiState.Idle, repository.state.value)
        verifyNoInteractions(manager)
    }

    @Test
    fun video_and_unknown_incoming_types_are_unavailable() = runTest {
        enableCalling()
        assertNull(repository.initiateCall(peer, true))
        for (type in listOf(1, -1, 2)) {
            repository.onIncoming(call, peer, type)
            assertFalse(repository.acceptCall(call, peer))
        }
        assertNull(repository.toggleVideo(call, peer))
        assertEquals(CallUiState.Idle, repository.state.value)
        verifyNoInteractions(manager)
    }

    @Test
    fun invalid_identity_and_mismatched_accept_never_reach_native() = runTest {
        enableCalling()
        assertNull(repository.initiateCall("phone-number", false))
        repository.onIncoming(call, "not-an-identity", 0)
        assertEquals(CallUiState.Idle, repository.state.value)
        repository.onIncoming(call, peer, 0)
        assertFalse(repository.acceptCall(call, "cd".repeat(32)))
        assertFalse(repository.acceptCall(replacement, peer))
        verifyNoInteractions(manager)
    }

    @Test
    fun accept_publishes_only_the_current_voice_call() = runTest {
        enableCalling()
        repository.onIncoming(call, peer, 0)
        `when`(manager.acceptCall(call, peer)).thenReturn(true)
        assertTrue(repository.acceptCall(call, peer))
        assertEquals(CallUiState.Active(call, peer, 0), repository.state.value)
        assertNull(repository.initiateCall(peer, false))
        verify(manager, never()).initiateCall(peer, 0)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun accept_result_does_not_restore_a_terminated_call_or_replace_a_new_invite() = runTest {
        enableCalling()
        repository.onIncoming(call, peer, 0)
        lateinit var pending: Continuation<Boolean>
        `when`(manager.acceptCall(call, peer)).thenAnswer {
            pending = it.rawArguments.last() as Continuation<Boolean>
            COROUTINE_SUSPENDED
        }
        val accepting = async { repository.acceptCall(call, peer) }
        runCurrent()
        repository.onStateChanged(call, "ended")
        repository.onIncoming(replacement, peer, 0)
        pending.resume(true)
        assertFalse(accepting.await())
        assertEquals(CallUiState.Incoming(replacement, peer, 0), repository.state.value)
        verify(manager).endCall(call, peer)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun initiate_result_does_not_restore_a_call_terminated_before_native_returns_its_id() = runTest {
        enableCalling()
        lateinit var pending: Continuation<String?>
        `when`(manager.initiateCall(peer, 0)).thenAnswer {
            pending = it.rawArguments.last() as Continuation<String?>
            COROUTINE_SUSPENDED
        }
        val initiating = async { repository.initiateCall(peer, false) }
        runCurrent()
        repository.onStateChanged(call, "error")
        pending.resume(call)
        assertNull(initiating.await())
        assertEquals(CallUiState.Idle, repository.state.value)
        verify(manager).endCall(call, peer)
    }

    @Test
    fun initiate_result_does_not_overwrite_an_incoming_call() = runTest {
        enableCalling()
        `when`(manager.initiateCall(peer, 0)).thenAnswer {
            repository.onIncoming(replacement, peer, 0)
            call
        }
        assertNull(repository.initiateCall(peer, false))
        assertEquals(CallUiState.Incoming(replacement, peer, 0), repository.state.value)
        verify(manager).endCall(call, peer)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun end_result_does_not_clear_a_new_invite_and_stale_end_is_rejected() = runTest {
        activate()
        lateinit var pending: Continuation<Boolean>
        `when`(manager.endCall(call, peer)).thenAnswer {
            pending = it.rawArguments.last() as Continuation<Boolean>
            COROUTINE_SUSPENDED
        }
        val ending = async { repository.endCall(call, peer) }
        runCurrent()
        repository.onStateChanged(call, "left")
        repository.onIncoming(replacement, peer, 0)
        pending.resume(true)
        assertTrue(ending.await())
        assertFalse(repository.endCall(call, peer))
        assertEquals(CallUiState.Incoming(replacement, peer, 0), repository.state.value)
        verify(manager, times(1)).endCall(call, peer)
    }

    @Test
    fun failed_native_end_still_clears_only_the_matching_call() = runTest {
        activate()
        `when`(manager.endCall(call, peer)).thenReturn(false)
        assertFalse(repository.endCall(call, peer))
        assertEquals(CallUiState.Idle, repository.state.value)
    }

    @Test
    fun unrelated_terminal_and_current_nonterminal_events_preserve_active_call() = runTest {
        activate()
        repository.onStateChanged(replacement, "ended")
        repository.onStateChanged(call, "active")
        repository.onIncoming(replacement, peer, 0)
        assertEquals(CallUiState.Active(call, peer, 0), repository.state.value)
        assertFalse(repository.endCall(call, "cd".repeat(32)))
        verify(manager, never()).endCall(call, "cd".repeat(32))
    }

    @Test
    fun identical_replacement_invite_is_not_promoted_by_an_old_accept_result() = runTest {
        enableCalling()
        repository.onIncoming(call, peer, 0)
        `when`(manager.acceptCall(call, peer)).thenAnswer {
            repository.onStateChanged(call, "ended")
            repository.onIncoming(call, peer, 0)
            true
        }
        assertFalse(repository.acceptCall(call, peer))
        assertEquals(CallUiState.Incoming(call, peer, 0), repository.state.value)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun suspended_mute_toggles_are_serialized() = runTest {
        activate()
        val pending = mutableListOf<Continuation<Boolean?>>()
        `when`(manager.toggleMute(call, peer)).thenAnswer {
            pending += it.rawArguments.last() as Continuation<Boolean?>
            COROUTINE_SUSPENDED
        }
        val first = async { repository.toggleMute(call, peer) }
        val second = async { repository.toggleMute(call, peer) }
        runCurrent()
        assertEquals(1, pending.size)
        pending[0].resume(true)
        runCurrent()
        assertTrue(first.await()!!)
        assertEquals(2, pending.size)
        pending[1].resume(false)
        assertFalse(second.await()!!)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun terminated_call_discards_pending_mute_result_and_queued_toggle() = runTest {
        activate()
        lateinit var pending: Continuation<Boolean?>
        `when`(manager.toggleMute(call, peer)).thenAnswer {
            pending = it.rawArguments.last() as Continuation<Boolean?>
            COROUTINE_SUSPENDED
        }
        val first = async { repository.toggleMute(call, peer) }
        val second = async { repository.toggleMute(call, peer) }
        runCurrent()
        repository.onStateChanged(call, "ended")
        repository.onIncoming(replacement, peer, 0)
        pending.resume(true)
        assertNull(first.await())
        assertNull(second.await())
        verify(manager, times(1)).toggleMute(call, peer)
        assertEquals(CallUiState.Incoming(replacement, peer, 0), repository.state.value)
    }
}
