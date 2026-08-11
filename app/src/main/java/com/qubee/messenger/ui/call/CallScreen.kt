package com.qubee.messenger.ui.call

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.VideocamOff
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.data.repository.CallRepository.CallUiState
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeeTheme

/**
 * Full-screen call overlay. Renders over the app content whenever a call
 * is ringing or active, driven by [CallViewModel.state] (which mirrors
 * the native CallManager via CallRepository). Renders nothing when idle.
 */
@Composable
fun CallOverlay(viewModel: CallViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val muted by viewModel.muted.collectAsStateWithLifecycle()
    val videoOn by viewModel.videoOn.collectAsStateWithLifecycle()

    when (val call = state) {
        is CallUiState.Idle -> Unit
        is CallUiState.Incoming -> IncomingCallBody(
            callerLabel = shortId(call.peerIdHex),
            isVideo = call.callType == CALL_TYPE_VIDEO,
            onAccept = viewModel::accept,
            onReject = viewModel::reject,
        )
        is CallUiState.Active -> ActiveCallBody(
            peerLabel = shortId(call.peerIdHex),
            isVideo = call.callType == CALL_TYPE_VIDEO,
            muted = muted,
            videoOn = videoOn,
            onToggleMute = viewModel::toggleMute,
            onToggleVideo = viewModel::toggleVideo,
            onHangUp = viewModel::hangUp,
        )
    }
}

/** Ringing screen: shows the caller and accept/reject controls. */
@Composable
internal fun IncomingCallBody(
    callerLabel: String,
    isVideo: Boolean,
    onAccept: () -> Unit,
    onReject: () -> Unit,
    modifier: Modifier = Modifier,
) {
    CallSurface(modifier) {
        CallHeader(
            title = callerLabel,
            subtitle = if (isVideo) "Incoming video call…" else "Incoming call…",
        )
        Spacer(Modifier.size(48.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            RoundCallButton(
                icon = Icons.Filled.CallEnd,
                tint = QubeePalette.Danger,
                contentDescription = "Reject call",
                onClick = onReject,
            )
            RoundCallButton(
                icon = Icons.Filled.Call,
                tint = QubeePalette.Green,
                contentDescription = "Accept call",
                onClick = onAccept,
            )
        }
    }
}

/** In-call screen: mute / video / hang-up controls. */
@Composable
internal fun ActiveCallBody(
    peerLabel: String,
    isVideo: Boolean,
    muted: Boolean,
    videoOn: Boolean,
    onToggleMute: () -> Unit,
    onToggleVideo: () -> Unit,
    onHangUp: () -> Unit,
    modifier: Modifier = Modifier,
) {
    CallSurface(modifier) {
        CallHeader(
            title = peerLabel,
            subtitle = if (isVideo) "Video call" else "Voice call",
        )
        Spacer(Modifier.size(48.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            RoundCallButton(
                icon = if (muted) Icons.Filled.MicOff else Icons.Filled.Mic,
                tint = if (muted) QubeePalette.Warning else QubeePalette.Text,
                contentDescription = if (muted) "Unmute" else "Mute",
                onClick = onToggleMute,
            )
            RoundCallButton(
                icon = Icons.Filled.CallEnd,
                tint = QubeePalette.Danger,
                contentDescription = "Hang up",
                onClick = onHangUp,
            )
            RoundCallButton(
                icon = if (videoOn) Icons.Filled.Videocam else Icons.Filled.VideocamOff,
                tint = if (videoOn) QubeePalette.Cyan else QubeePalette.MutedText,
                contentDescription = if (videoOn) "Turn video off" else "Turn video on",
                onClick = onToggleVideo,
            )
        }
    }
}

@Composable
private fun CallSurface(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Surface(color = QubeePalette.Void, modifier = modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) { content() }
    }
}

@Composable
private fun CallHeader(title: String, subtitle: String) {
    Text(
        text = title,
        color = QubeePalette.Text,
        fontSize = 26.sp,
        fontWeight = FontWeight.SemiBold,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.size(8.dp))
    Text(
        text = subtitle,
        color = QubeePalette.MutedText,
        fontSize = 15.sp,
        textAlign = TextAlign.Center,
    )
}

@Composable
private fun RoundCallButton(
    icon: ImageVector,
    tint: Color,
    contentDescription: String,
    onClick: () -> Unit,
) {
    Surface(
        color = QubeePalette.PanelAlt,
        shape = CircleShape,
        onClick = onClick,
        modifier = Modifier.size(68.dp),
    ) {
        Box(contentAlignment = Alignment.Center) {
            Icon(
                imageVector = icon,
                contentDescription = contentDescription,
                tint = tint,
                modifier = Modifier.size(30.dp),
            )
        }
    }
}

/** Call type codes shared with the native layer (see CallType in Rust). */
internal const val CALL_TYPE_VOICE = 0
internal const val CALL_TYPE_VIDEO = 1

/** Abbreviate a 64-char identity hex to something a human can glance at. */
internal fun shortId(hex: String): String =
    if (hex.length <= 12) hex else "${hex.take(6)}…${hex.takeLast(6)}"

@Preview
@Composable
private fun IncomingCallPreview() {
    QubeeTheme {
        IncomingCallBody(
            callerLabel = shortId("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
            isVideo = false,
            onAccept = {},
            onReject = {},
        )
    }
}

@Preview
@Composable
private fun ActiveCallPreview() {
    QubeeTheme {
        ActiveCallBody(
            peerLabel = shortId("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
            isVideo = true,
            muted = true,
            videoOn = true,
            onToggleMute = {},
            onToggleVideo = {},
            onHangUp = {},
        )
    }
}
