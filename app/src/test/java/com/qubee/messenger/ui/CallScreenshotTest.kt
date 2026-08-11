package com.qubee.messenger.ui

import com.qubee.messenger.ui.call.ActiveCallBody
import com.qubee.messenger.ui.call.IncomingCallBody
import org.junit.Rule
import org.junit.Test

/** Baselines for the call overlay: a ringing incoming call and an
 * in-progress active call with mute engaged. Drives the stateless call
 * bodies with fabricated state — no ViewModel, JNI, or network. */
class CallScreenshotTest {

    @get:Rule
    val paparazzi = paparazziRule()

    @Test
    fun incoming_voice_call() {
        paparazzi.snapshotThemed {
            IncomingCallBody(
                callerLabel = "a1b2c3…d5e6f7",
                isVideo = false,
                onAccept = {},
                onReject = {},
            )
        }
    }

    @Test
    fun active_video_call_muted() {
        paparazzi.snapshotThemed {
            ActiveCallBody(
                peerLabel = "a1b2c3…d5e6f7",
                isVideo = true,
                muted = true,
                videoOn = true,
                onToggleMute = {},
                onToggleVideo = {},
                onHangUp = {},
            )
        }
    }
}
