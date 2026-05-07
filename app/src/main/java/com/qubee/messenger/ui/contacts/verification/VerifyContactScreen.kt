package com.qubee.messenger.ui.contacts.verification

import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.util.QrUtils

/**
 * Full-screen identity verification surface hosted by
 * [ContactVerificationActivity]. Same trust ceremony as the
 * in-chat `VerifyContactDialog`, laid out as a Scaffold instead
 * of an `AlertDialog` so it has room for the SAS, the typed
 * fingerprint field, and the local user's QR side-by-side.
 *
 * Two routes lead to `TrustLevel.VERIFIED`:
 *
 *   1. Type or scan the contact's fingerprint → match against
 *      their stored `IdentityKey` via the Rust `verifyIdentityKey`
 *      JNI export. Mismatches keep the screen open.
 *
 *   2. Tap "Codes match" on the SAS pane after both devices
 *      independently confirm the same 8-digit code. The user's
 *      attestation IS the trust ceremony — there's no bridge
 *      round-trip.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifyContactScreen(
    viewModel: ContactVerificationViewModel,
    onClose: () -> Unit,
    onScanQr: () -> Unit,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is ContactVerificationEvent.Notice ->
                    snackbarHostState.showSnackbar(event.message)
                ContactVerificationEvent.Verified ->
                    snackbarHostState.showSnackbar("Verified — trust level is now VERIFIED.")
            }
        }
    }

    Scaffold(
        containerColor = QubeePalette.Void,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Verify contact", color = QubeePalette.Text) },
                navigationIcon = {
                    IconButton(onClick = onClose) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = QubeePalette.Text,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = QubeePalette.Void,
                ),
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when {
                state.isLoading -> LoadingContent()
                state.loadError != null -> LoadErrorContent(state.loadError!!, onClose)
                else -> VerifyContent(
                    state = state,
                    onTypedFingerprintChange = viewModel::onTypedFingerprintChange,
                    onConfirmFingerprint = viewModel::confirmFingerprintMatch,
                    onConfirmSas = viewModel::confirmSasMatch,
                    onScanQr = onScanQr,
                )
            }
        }
    }
}

@Composable
private fun LoadingContent() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(color = QubeePalette.Cyan)
    }
}

@Composable
private fun LoadErrorContent(message: String, onClose: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "Couldn't load contact",
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(8.dp))
        QubeeMutedText(text = message)
        Spacer(Modifier.height(24.dp))
        QubeePrimaryButton(text = "Close", onClick = onClose)
    }
}

@Composable
private fun VerifyContent(
    state: ContactVerificationUiState,
    onTypedFingerprintChange: (String) -> Unit,
    onConfirmFingerprint: () -> Unit,
    onConfirmSas: () -> Unit,
    onScanQr: () -> Unit,
) {
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(horizontal = 22.dp, vertical = 18.dp),
    ) {
        QubeeStatusPill(
            text = if (state.alreadyVerified) "ALREADY VERIFIED" else "OOB COMPARE",
        )
        Spacer(Modifier.height(10.dp))
        Text(
            text = state.contactName,
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Black,
        )
        Spacer(Modifier.height(4.dp))
        QubeeMutedText(
            text = "Compare codes over a separate channel — voice call, in person, " +
                "or another already-trusted app. The two devices compute the same " +
                "value if no one's tampering with the link.",
        )

        Spacer(Modifier.height(20.dp))
        FingerprintBlock(
            fingerprint = state.contactFingerprint,
            typed = state.typedFingerprint,
            onTypedChange = onTypedFingerprintChange,
            onScanQr = onScanQr,
            onConfirm = onConfirmFingerprint,
        )

        if (state.myFingerprint != null) {
            Spacer(Modifier.height(20.dp))
            Divider(color = QubeePalette.PanelAlt)
            Spacer(Modifier.height(20.dp))
            MyFingerprintBlock(myFingerprint = state.myFingerprint)
        }

        if (state.sasCode != null) {
            Spacer(Modifier.height(20.dp))
            Divider(color = QubeePalette.PanelAlt)
            Spacer(Modifier.height(20.dp))
            SasBlock(sas = state.sasCode, onConfirm = onConfirmSas)
        }

        Spacer(Modifier.height(28.dp))
    }
}

@Composable
private fun FingerprintBlock(
    fingerprint: String,
    typed: String,
    onTypedChange: (String) -> Unit,
    onScanQr: () -> Unit,
    onConfirm: () -> Unit,
) {
    Text(
        text = "Their fingerprint as we see it",
        color = QubeePalette.Text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    Spacer(Modifier.height(8.dp))
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = QubeePalette.PanelAlt,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = fingerprint.ifBlank { "Not available" },
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold,
            color = QubeePalette.Text,
            style = MaterialTheme.typography.titleMedium,
        )
    }
    Spacer(Modifier.height(14.dp))
    OutlinedTextField(
        value = typed,
        onValueChange = onTypedChange,
        label = { Text("Fingerprint from contact") },
        placeholder = { Text("AABB CCDD EEFF GGHH") },
        singleLine = false,
        modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(8.dp))
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        OutlinedButton(
            onClick = onScanQr,
            modifier = Modifier.weight(1f),
        ) {
            Icon(
                imageVector = Icons.Filled.QrCodeScanner,
                contentDescription = null,
                tint = QubeePalette.Cyan,
            )
            Spacer(Modifier.width(8.dp))
            Text("Scan QR", color = QubeePalette.Cyan)
        }
        QubeePrimaryButton(
            text = "Verify",
            onClick = onConfirm,
            enabled = typed.isNotBlank(),
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun MyFingerprintBlock(myFingerprint: String) {
    Text(
        text = "Let them scan you",
        color = QubeePalette.Text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    Spacer(Modifier.height(6.dp))
    QubeeMutedText(
        text = "Show this QR to their device. Their verify screen scans it to " +
            "confirm your identity at the same time you're confirming theirs.",
    )
    Spacer(Modifier.height(12.dp))
    val bitmap = remember(myFingerprint) {
        QrUtils.encodeAsBitmap(myFingerprint, sizePx = 540)
    }
    if (bitmap != null) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = Color.White,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Box(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                contentAlignment = Alignment.Center,
            ) {
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = "Your verification QR code",
                    modifier = Modifier.size(220.dp),
                )
            }
        }
        Spacer(Modifier.height(8.dp))
    }
    Text(
        text = myFingerprint,
        modifier = Modifier.fillMaxWidth(),
        textAlign = TextAlign.Center,
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.SemiBold,
        color = QubeePalette.Text,
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun SasBlock(sas: String, onConfirm: () -> Unit) {
    Text(
        text = "Or compare a SAS code",
        color = QubeePalette.Text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    Spacer(Modifier.height(8.dp))
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = QubeePalette.Cyan.copy(alpha = 0.18f),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(
            modifier = Modifier.fillMaxWidth().padding(20.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = sas,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                color = QubeePalette.Cyan,
                style = MaterialTheme.typography.headlineMedium,
                textAlign = TextAlign.Center,
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    QubeeMutedText(
        text = "Both devices show the same digits when nothing's intercepting. " +
            "If they match, tap below.",
    )
    Spacer(Modifier.height(12.dp))
    QubeePrimaryButton(
        text = "Codes match",
        onClick = onConfirm,
        modifier = Modifier.fillMaxWidth(),
    )
}
