package com.qubee.messenger.calling

import android.media.AudioRecord
import android.media.AudioTrack
import com.qubee.messenger.crypto.QubeeManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.mockito.Mockito.doThrow
import org.mockito.Mockito.mock
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.Mockito.verifyNoInteractions
import org.mockito.Mockito.verifyNoMoreInteractions
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean

class AudioCallEngineTest {
    private val manager = mock(QubeeManager::class.java)
    private val engine = AudioCallEngine(manager)

    private fun field(name: String) = AudioCallEngine::class.java.getDeclaredField(name).apply {
        isAccessible = true
    }

    private fun running() = field("running").get(engine) as AtomicBoolean

    @Suppress("UNCHECKED_CAST")
    private fun frames() = field("remoteFrames").get(engine) as LinkedBlockingQueue<ByteArray>

    @Test
    fun fresh_stop_is_idempotent_and_never_reaches_native() {
        engine.stop()
        engine.stop()
        engine.onRemoteAudioFrame(byteArrayOf(1))

        assertFalse(running().get())
        assertEquals(0, frames().size)
        assertNull(field("captureThread").get(engine))
        assertNull(field("playbackThread").get(engine))
        verifyNoInteractions(manager)
    }

    @Test
    fun stop_explicitly_stops_active_devices_once_across_repeated_teardown() {
        val record = mock(AudioRecord::class.java)
        val track = mock(AudioTrack::class.java)
        field("activeRecord").set(engine, record)
        field("activeTrack").set(engine, track)
        running().set(true)

        engine.stop()
        engine.stop()

        assertFalse(running().get())
        verify(record, times(1)).stop()
        verify(track, times(1)).stop()
        verifyNoMoreInteractions(record, track)
        verifyNoInteractions(manager)
    }

    @Test
    fun recorder_stop_failure_does_not_skip_track_stop_or_reenable_running() {
        val record = mock(AudioRecord::class.java)
        val track = mock(AudioTrack::class.java)
        doThrow(IllegalStateException("Already stopped")).`when`(record).stop()
        field("activeRecord").set(engine, record)
        field("activeTrack").set(engine, track)
        running().set(true)

        engine.stop()
        engine.stop()

        assertFalse(running().get())
        verify(record, times(1)).stop()
        verify(track, times(1)).stop()
        verifyNoInteractions(manager)
    }

    @Test
    fun already_running_start_does_not_spawn_workers_and_stop_disables_media() {
        running().set(true)
        engine.onRemoteAudioFrame(byteArrayOf(1))
        assertEquals(1, frames().size)

        engine.start("call-id", "peer-id")
        assertNull(field("captureThread").get(engine))
        assertNull(field("playbackThread").get(engine))
        engine.stop()
        assertFalse(running().get())
        assertEquals(1, frames().size)
        assertEquals(0, frames().peek().size)

        engine.onRemoteAudioFrame(byteArrayOf(2))
        assertEquals(1, frames().size)
        assertEquals(0, frames().peek().size)
        verifyNoInteractions(manager)
    }
}
