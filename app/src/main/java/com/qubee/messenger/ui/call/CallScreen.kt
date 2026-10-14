package com.qubee.messenger.ui.call

import android.Manifest
import android.content.pm.PackageManager
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.VideocamOff
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.BuildConfig
import com.qubee.messenger.R
import com.qubee.messenger.calling.VideoSurfaces
import com.qubee.messenger.data.repository.CallRepository.CallUiState
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeMono
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeeStatusPill
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
    val context = LocalContext.current
    val microphonePermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) viewModel.accept()
    }

    when (val call = state) {
        is CallUiState.Idle -> Unit
        is CallUiState.Incoming -> IncomingCallBody(
            callerLabel = shortId(call.peerIdHex),
            isVideo = false,
            onAccept = {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                    viewModel.accept()
                } else {
                    microphonePermission.launch(Manifest.permission.RECORD_AUDIO)
                }
            },
            onReject = viewModel::reject,
        )
        is CallUiState.Active -> ActiveCallBody(
            peerLabel = shortId(call.peerIdHex),
            isVideo = false,
            muted = muted,
            videoOn = false,
            onToggleMute = viewModel::toggleMute,
            onToggleVideo = {},
            onHangUp = viewModel::hangUp,
            showVideoControls = BuildConfig.CALLING_VIDEO_ENABLED,
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
            subtitle = stringResource(if (isVideo) R.string.call_incoming_video else R.string.call_incoming),
        )
        Spacer(Modifier.height(56.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            RoundCallButton(
                icon = Icons.Filled.CallEnd,
                label = stringResource(R.string.call_decline),
                tint = QubeePalette.Text,
                background = QubeePalette.Danger,
                onClick = onReject,
            )
            RoundCallButton(
                icon = Icons.Filled.Call,
                label = stringResource(R.string.call_answer),
                tint = QubeePalette.Void,
                background = QubeePalette.Green,
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
    showVideoControls: Boolean = true,
) {
    CallSurface(modifier) {
        CallHeader(
            title = peerLabel,
            subtitle = stringResource(if (isVideo) R.string.call_video else R.string.call_voice),
        )
        if (showVideoControls && (isVideo || videoOn)) {
            Spacer(Modifier.height(24.dp))
            RemoteVideoSurface(
                Modifier
                    .fillMaxWidth()
                    .height(260.dp)
                    .clip(RoundedCornerShape(20.dp)),
            )
        }
        Spacer(Modifier.height(48.dp))
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            RoundCallButton(
                icon = if (muted) Icons.Filled.MicOff else Icons.Filled.Mic,
                label = stringResource(if (muted) R.string.call_unmute else R.string.call_mute),
                tint = if (muted) QubeePalette.Warning else QubeePalette.Text,
                background = QubeePalette.PanelAlt,
                onClick = onToggleMute,
            )
            RoundCallButton(
                icon = Icons.Filled.CallEnd,
                label = stringResource(R.string.call_hang_up),
                tint = QubeePalette.Text,
                background = QubeePalette.Danger,
                onClick = onHangUp,
            )
            if (showVideoControls) {
                RoundCallButton(
                    icon = if (videoOn) Icons.Filled.Videocam else Icons.Filled.VideocamOff,
                    label = stringResource(if (videoOn) R.string.call_video_on else R.string.call_video_off),
                    tint = if (videoOn) QubeePalette.Cyan else QubeePalette.MutedText,
                    background = QubeePalette.PanelAlt,
                    onClick = onToggleVideo,
                )
            }
        }
    }
}

/** Hosts the decoder's output surface; publishes/clears it in [VideoSurfaces] as the view is created/destroyed. */
@Composable
private fun RemoteVideoSurface(modifier: Modifier = Modifier) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            SurfaceView(context).apply {
                holder.addCallback(object : SurfaceHolder.Callback {
                    override fun surfaceCreated(holder: SurfaceHolder) {
                        VideoSurfaces.remote = holder.surface
                    }

                    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
                        VideoSurfaces.remote = holder.surface
                    }

                    override fun surfaceDestroyed(holder: SurfaceHolder) {
                        if (VideoSurfaces.remote === holder.surface) VideoSurfaces.remote = null
                    }
                })
            }
        },
    )
    DisposableEffect(Unit) {
        onDispose { VideoSurfaces.remote = null }
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
    QubeeAvatar(initials = "", size = 96.dp, icon = Icons.Outlined.Lock)
    Spacer(Modifier.height(22.dp))
    Text(
        text = title,
        color = QubeePalette.Text,
        style = MaterialTheme.typography.headlineMedium,
        fontFamily = QubeeMono,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(8.dp))
    QubeeMutedText(subtitle, style = MaterialTheme.typography.bodyLarge)
    Spacer(Modifier.height(14.dp))
    QubeeStatusPill(text = stringResource(R.string.call_private), color = QubeePalette.Green, dot = true)
}

@Composable
private fun RoundCallButton(
    icon: ImageVector,
    label: String,
    tint: Color,
    background: Color,
    onClick: () -> Unit,
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Surface(
            color = background,
            shape = CircleShape,
            onClick = onClick,
            modifier = Modifier.size(68.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = tint,
                    modifier = Modifier.size(30.dp),
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        Text(
            text = label,
            color = QubeePalette.MutedText,
            style = MaterialTheme.typography.labelMedium,
        )
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
