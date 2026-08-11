package com.qubee.messenger.calling

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaFormat
import android.media.MediaRecorder
import com.qubee.messenger.crypto.QubeeManager
import timber.log.Timber
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Audio half of a WebRTC call: captures the mic, Opus-encodes, and pushes
 * frames into the call's outbound track via [QubeeManager.writeAudioSample];
 * and Opus-decodes remote frames delivered to [onRemoteAudioFrame],
 * playing them back through [AudioTrack].
 *
 * The Rust/WebRTC side is codec-agnostic — it packetizes whatever Opus
 * bitstream we hand it and hands us back the peer's Opus packets — so all
 * codec work lives here.
 *
 * **This has never run on hardware.** It compiles and follows the
 * documented `MediaCodec`/`AudioRecord`/`AudioTrack` contracts, but the
 * fiddly bits — whether the device ships a `MediaCodec` Opus *encoder*
 * (not universal), the exact Opus decoder CSD headers, buffer timing,
 * and echo/AGC — must be validated on a physical device. Treat it as a
 * reviewed scaffold, not a proven pipeline.
 */
class AudioCallEngine(private val qubeeManager: QubeeManager) {

    private val running = AtomicBoolean(false)
    private var captureThread: Thread? = null
    private var playbackThread: Thread? = null

    // Opus packets received from the remote track, awaiting decode+playback.
    private val remoteFrames = LinkedBlockingQueue<ByteArray>()

    @Volatile private var callIdHex: String = ""
    @Volatile private var peerIdHex: String = ""

    /** Begin capturing the mic for [callIdHex] and playing [peerIdHex]'s audio. */
    fun start(callIdHex: String, peerIdHex: String) {
        if (!running.compareAndSet(false, true)) return
        this.callIdHex = callIdHex
        this.peerIdHex = peerIdHex
        remoteFrames.clear()
        captureThread = Thread({ runCapture() }, "call-audio-capture").apply { start() }
        playbackThread = Thread({ runPlayback() }, "call-audio-playback").apply { start() }
    }

    /** Stop capture + playback and release all codecs/devices. */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        // Unblock the playback thread's queue take().
        remoteFrames.offer(POISON)
        captureThread?.join(TEARDOWN_JOIN_MS)
        playbackThread?.join(TEARDOWN_JOIN_MS)
        captureThread = null
        playbackThread = null
    }

    /** Hand an Opus packet from the remote track to the playback decoder. */
    fun onRemoteAudioFrame(opus: ByteArray) {
        if (running.get()) remoteFrames.offer(opus)
    }

    // --- Capture: mic → Opus → writeAudioSample --------------------------

    private fun runCapture() {
        var record: AudioRecord? = null
        var encoder: MediaCodec? = null
        try {
            val minBuf = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_IN, PCM_ENCODING)
            val bufferBytes = maxOf(minBuf, FRAME_BYTES * 4)
            record = AudioRecord(
                MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                SAMPLE_RATE,
                CHANNEL_IN,
                PCM_ENCODING,
                bufferBytes,
            )
            if (record.state != AudioRecord.STATE_INITIALIZED) {
                Timber.w("AudioRecord failed to initialize; no mic capture")
                return
            }

            encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
            val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, SAMPLE_RATE, 1).apply {
                setInteger(MediaFormat.KEY_BIT_RATE, BIT_RATE)
                setInteger(
                    MediaFormat.KEY_PCM_ENCODING,
                    AudioFormat.ENCODING_PCM_16BIT,
                )
                setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, FRAME_BYTES * 2)
            }
            encoder.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            encoder.start()
            record.startRecording()

            val pcm = ByteArray(FRAME_BYTES)
            val info = MediaCodec.BufferInfo()
            var ptsUs = 0L
            while (running.get()) {
                val read = record.read(pcm, 0, pcm.size)
                if (read <= 0) continue

                val inIndex = encoder.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                if (inIndex >= 0) {
                    val inBuf = encoder.getInputBuffer(inIndex) ?: continue
                    inBuf.clear()
                    inBuf.put(pcm, 0, read)
                    encoder.queueInputBuffer(inIndex, 0, read, ptsUs, 0)
                    ptsUs += FRAME_DURATION_US
                }

                var outIndex = encoder.dequeueOutputBuffer(info, DEQUEUE_TIMEOUT_US)
                while (outIndex >= 0) {
                    if (info.size > 0 && info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0) {
                        val outBuf = encoder.getOutputBuffer(outIndex)
                        if (outBuf != null) {
                            val frame = ByteArray(info.size)
                            outBuf.position(info.offset)
                            outBuf.get(frame, 0, info.size)
                            qubeeManager.writeAudioSample(callIdHex, peerIdHex, frame, FRAME_DURATION_MS)
                        }
                    }
                    encoder.releaseOutputBuffer(outIndex, false)
                    outIndex = encoder.dequeueOutputBuffer(info, 0)
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Audio capture loop failed")
        } finally {
            runCatching { record?.stop() }
            runCatching { record?.release() }
            runCatching { encoder?.stop() }
            runCatching { encoder?.release() }
        }
    }

    // --- Playback: Opus → PCM → AudioTrack -------------------------------

    private fun runPlayback() {
        var decoder: MediaCodec? = null
        var track: AudioTrack? = null
        try {
            decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS)
            val format = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, SAMPLE_RATE, 1).apply {
                // Android's Opus decoder expects three codec-specific-data
                // buffers: the OpusHead identification header, then the
                // codec delay and seek pre-roll as 8-byte little-endian
                // nanosecond values.
                setByteBuffer("csd-0", opusHead())
                setByteBuffer("csd-1", nanosLe(PRE_SKIP_NS))
                setByteBuffer("csd-2", nanosLe(PRE_SKIP_NS))
            }
            decoder.configure(format, null, null, 0)
            decoder.start()

            val minBuf = AudioTrack.getMinBufferSize(SAMPLE_RATE, CHANNEL_OUT, PCM_ENCODING)
            track = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build(),
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setEncoding(PCM_ENCODING)
                        .setSampleRate(SAMPLE_RATE)
                        .setChannelMask(CHANNEL_OUT)
                        .build(),
                )
                .setBufferSizeInBytes(maxOf(minBuf, FRAME_BYTES * 4))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
            track.play()

            val info = MediaCodec.BufferInfo()
            var ptsUs = 0L
            while (running.get()) {
                val opus = remoteFrames.take()
                if (opus === POISON) break

                val inIndex = decoder.dequeueInputBuffer(DEQUEUE_TIMEOUT_US)
                if (inIndex >= 0) {
                    val inBuf = decoder.getInputBuffer(inIndex) ?: continue
                    inBuf.clear()
                    inBuf.put(opus)
                    decoder.queueInputBuffer(inIndex, 0, opus.size, ptsUs, 0)
                    ptsUs += FRAME_DURATION_US
                }

                var outIndex = decoder.dequeueOutputBuffer(info, DEQUEUE_TIMEOUT_US)
                while (outIndex >= 0) {
                    if (info.size > 0) {
                        val outBuf = decoder.getOutputBuffer(outIndex)
                        if (outBuf != null) {
                            val pcm = ByteArray(info.size)
                            outBuf.position(info.offset)
                            outBuf.get(pcm, 0, info.size)
                            track.write(pcm, 0, pcm.size)
                        }
                    }
                    decoder.releaseOutputBuffer(outIndex, false)
                    outIndex = decoder.dequeueOutputBuffer(info, 0)
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Audio playback loop failed")
        } finally {
            runCatching { track?.stop() }
            runCatching { track?.release() }
            runCatching { decoder?.stop() }
            runCatching { decoder?.release() }
        }
    }

    /** Build the 19-byte OpusHead identification header (mono, 48 kHz). */
    private fun opusHead(): ByteBuffer {
        val head = ByteBuffer.allocate(19).order(ByteOrder.LITTLE_ENDIAN)
        head.put("OpusHead".toByteArray(Charsets.US_ASCII)) // magic (8)
        head.put(1)                                          // version
        head.put(1)                                          // channel count
        head.putShort(PRE_SKIP_SAMPLES.toShort())            // pre-skip
        head.putInt(SAMPLE_RATE)                             // input sample rate
        head.putShort(0)                                     // output gain
        head.put(0)                                          // channel mapping family
        head.flip()
        return head
    }

    private fun nanosLe(nanos: Long): ByteBuffer =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(nanos).apply { flip() }

    private companion object {
        const val SAMPLE_RATE = 48_000
        const val CHANNEL_IN = AudioFormat.CHANNEL_IN_MONO
        const val CHANNEL_OUT = AudioFormat.CHANNEL_OUT_MONO
        const val PCM_ENCODING = AudioFormat.ENCODING_PCM_16BIT
        const val BIT_RATE = 24_000
        const val FRAME_DURATION_MS = 20
        const val FRAME_DURATION_US = 20_000L
        // 20 ms of 48 kHz mono 16-bit PCM = 960 samples * 2 bytes.
        const val FRAME_BYTES = SAMPLE_RATE / 1000 * FRAME_DURATION_MS * 2
        const val PRE_SKIP_SAMPLES = 3_840
        const val PRE_SKIP_NS = PRE_SKIP_SAMPLES.toLong() * 1_000_000_000L / SAMPLE_RATE
        const val DEQUEUE_TIMEOUT_US = 10_000L
        const val TEARDOWN_JOIN_MS = 500L
        val POISON = ByteArray(0)
    }
}
