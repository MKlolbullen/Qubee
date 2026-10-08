package com.qubee.messenger.calling

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Handler
import android.os.HandlerThread
import android.util.Range
import android.view.Surface
import androidx.core.content.ContextCompat
import com.qubee.messenger.crypto.QubeeManager
import timber.log.Timber
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Camera capture and remote VP8 decode for an identity-to-identity
 * session. Frames are complete access units, already reassembled from
 * RTP on the Rust side. The camera stays off until the user turns video
 * on. A missing encoder or permission fails closed and leaves audio up.
 */
class VideoCallEngine(
    private val context: Context,
    private val qubeeManager: QubeeManager,
) {
    private val running = AtomicBoolean(false)
    private val captureRunning = AtomicBoolean(false)
    private val lock = Any()
    private var callIdHex = ""
    private var peerIdHex = ""
    private var cameraThread: HandlerThread? = null
    private var cameraHandler: Handler? = null
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var encoder: MediaCodec? = null
    private var encoderSurface: Surface? = null
    private var drainThread: Thread? = null
    private var decoder: MediaCodec? = null
    private var decoderSurface: Surface? = null

    /** Binds this engine to a call/peer pair. Capture and decode stay off until explicitly enabled. */
    fun start(callId: String, peerId: String) {
        callIdHex = callId
        peerIdHex = peerId
        running.set(true)
    }

    /** Toggles the local camera. A missing permission or encoder fails closed and leaves audio running. */
    fun setCaptureEnabled(enabled: Boolean) {
        if (!running.get()) return
        if (!enabled) {
            stopCapture()
            return
        }
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            Timber.w("Camera permission missing; video capture stays off")
            return
        }
        if (encoder != null) return
        startCapture()
    }

    /** Feeds one already-reassembled VP8 access unit to the decoder bound to the active remote surface. */
    fun onRemoteAccessUnit(frame: ByteArray) {
        if (!running.get() || frame.isEmpty() || frame.size > MAX_ACCESS_UNIT) return
        val surface = VideoSurfaces.remote ?: return
        synchronized(lock) {
            val current = decoder
            if (current == null || decoderSurface !== surface) {
                releaseDecoderLocked()
                decoder = startDecoder(surface)
                decoderSurface = surface
            }
            val codec = decoder ?: return
            val index = codec.dequeueInputBuffer(0)
            if (index >= 0) {
                val buffer = codec.getInputBuffer(index) ?: return
                buffer.clear()
                if (buffer.remaining() < frame.size) {
                    codec.queueInputBuffer(index, 0, 0, System.nanoTime() / 1000, 0)
                    return
                }
                buffer.put(frame)
                codec.queueInputBuffer(index, 0, frame.size, System.nanoTime() / 1000, 0)
            }
            val info = MediaCodec.BufferInfo()
            var out = codec.dequeueOutputBuffer(info, 0)
            while (out >= 0) {
                codec.releaseOutputBuffer(out, info.size > 0)
                out = codec.dequeueOutputBuffer(info, 0)
            }
        }
    }

    /** Tears down capture and decode; safe to call even if video was never started. */
    fun stop() {
        running.set(false)
        stopCapture()
        synchronized(lock) { releaseDecoderLocked() }
    }

    /** Spins up the VP8 encoder and its camera source; falls back to audio-only on any failure. */
    private fun startCapture() {
        val thread = HandlerThread("qubee-camera").also { it.start() }
        val handler = Handler(thread.looper)
        cameraThread = thread
        cameraHandler = handler
        val codec = runCatching { MediaCodec.createEncoderByType(MIME) }.getOrElse {
            Timber.e(it, "VP8 encoder unavailable")
            thread.quitSafely()
            return
        }
        val format = MediaFormat.createVideoFormat(MIME, WIDTH, HEIGHT).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT, android.media.MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, BIT_RATE)
            setInteger(MediaFormat.KEY_FRAME_RATE, FRAME_RATE)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 2)
        }
        val started = runCatching {
            codec.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            val surface = codec.createInputSurface()
            codec.start()
            encoder = codec
            encoderSurface = surface
            captureRunning.set(true)
            surface
        }.getOrElse {
            Timber.e(it, "VP8 encoder failed to start")
            runCatching { codec.release() }
            thread.quitSafely()
            return
        }
        drainThread = Thread({ drainEncoder() }, "qubee-video-drain").also { it.start() }
        openCamera(started, handler)
    }

    /** Opens the front-facing camera (or the first available) and streams it into the encoder surface. */
    private fun openCamera(target: Surface, handler: Handler) {
        val manager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val id = runCatching {
            manager.cameraIdList.firstOrNull { cameraId ->
                val facing = manager.getCameraCharacteristics(cameraId)
                    .get(android.hardware.camera2.CameraCharacteristics.LENS_FACING)
                facing == android.hardware.camera2.CameraCharacteristics.LENS_FACING_FRONT
            } ?: manager.cameraIdList.firstOrNull()
        }.getOrNull()
        if (id == null) {
            Timber.w("No camera on this device")
            stopCapture()
            return
        }
        val callback = object : CameraDevice.StateCallback() {
            override fun onOpened(device: CameraDevice) {
                if (!captureRunning.get()) {
                    device.close()
                    return
                }
                camera = device
                val request = device.createCaptureRequest(CameraDevice.TEMPLATE_RECORD).apply {
                    addTarget(target)
                    set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, Range(FRAME_RATE, FRAME_RATE))
                }
                device.createCaptureSession(
                    listOf(target),
                    object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(capture: CameraCaptureSession) {
                            if (!captureRunning.get()) {
                                capture.close()
                                return
                            }
                            session = capture
                            runCatching {
                                capture.setRepeatingRequest(request.build(), null, handler)
                            }.onFailure { Timber.e(it, "camera repeating request failed") }
                        }

                        override fun onConfigureFailed(capture: CameraCaptureSession) {
                            Timber.e("camera session configure failed")
                        }
                    },
                    handler,
                )
            }

            override fun onDisconnected(device: CameraDevice) {
                device.close()
                if (camera === device) camera = null
            }

            override fun onError(device: CameraDevice, error: Int) {
                Timber.e("camera error %d", error)
                device.close()
                if (camera === device) camera = null
            }
        }
        runCatching { manager.openCamera(id, callback, handler) }
            .onFailure {
                Timber.e(it, "openCamera failed")
                stopCapture()
            }
    }

    /** Pulls encoded access units off the encoder and ships each to the peer, dropping any over `MAX_ACCESS_UNIT`. */
    private fun drainEncoder() {
        val info = MediaCodec.BufferInfo()
        while (captureRunning.get() && encoder != null) {
            val codec = encoder ?: break
            val index = runCatching { codec.dequeueOutputBuffer(info, 10_000) }.getOrDefault(-1)
            if (index < 0) continue
            if (info.size > 0 && info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0 && info.size <= MAX_ACCESS_UNIT) {
                val buffer = codec.getOutputBuffer(index)
                if (buffer != null) {
                    val frame = ByteArray(info.size)
                    buffer.position(info.offset)
                    buffer.get(frame, 0, info.size)
                    qubeeManager.writeVideoSample(callIdHex, peerIdHex, frame, FRAME_DURATION_MS)
                }
            }
            runCatching { codec.releaseOutputBuffer(index, false) }
        }
    }

    /** Builds a fresh VP8 decoder bound to `surface`, or null if the device has none. */
    private fun startDecoder(surface: Surface): MediaCodec? {
        return runCatching {
            val codec = MediaCodec.createDecoderByType(MIME)
            val format = MediaFormat.createVideoFormat(MIME, WIDTH, HEIGHT)
            codec.configure(format, surface, null, 0)
            codec.start()
            codec
        }.getOrElse {
            Timber.e(it, "VP8 decoder failed to start")
            null
        }
    }

    /** Releases the camera, encoder, and drain thread so capture can be restarted cleanly. */
    private fun stopCapture() {
        captureRunning.set(false)
        runCatching { session?.close() }
        session = null
        runCatching { camera?.close() }
        camera = null
        drainThread?.join(500)
        drainThread = null
        runCatching { encoder?.stop() }
        runCatching { encoder?.release() }
        encoder = null
        runCatching { encoderSurface?.release() }
        encoderSurface = null
        cameraThread?.quitSafely()
        cameraThread = null
        cameraHandler = null
    }

    /** Releases the current decoder. Caller must hold `lock`. */
    private fun releaseDecoderLocked() {
        runCatching { decoder?.stop() }
        runCatching { decoder?.release() }
        decoder = null
        decoderSurface = null
    }

    companion object {
        private const val MIME = MediaFormat.MIMETYPE_VIDEO_VP8
        private const val WIDTH = 640
        private const val HEIGHT = 480
        private const val FRAME_RATE = 15
        private const val FRAME_DURATION_MS = 66
        private const val BIT_RATE = 400_000
        private const val MAX_ACCESS_UNIT = 128 * 1024
    }
}

/** Remote render target set by the call overlay. */
object VideoSurfaces {
    @Volatile
    var remote: Surface? = null
}
