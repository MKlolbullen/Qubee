package com.qubee.messenger.ui.contacts.verification

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.R
import com.qubee.messenger.ui.theme.QubeeDangerButton
import com.qubee.messenger.ui.theme.QubeeMono
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQrCard
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeSectionLabel
import com.qubee.messenger.ui.theme.QubeeTextField
import com.qubee.messenger.ui.theme.QubeeTopBar
import com.qubee.messenger.util.QrUtils

/**
 * Full-screen identity confirmation hosted by [ContactVerificationActivity].
 * The short code both phones compute is the main path; the typed or
 * scanned fingerprint and the local QR stay below it for people who
 * prefer them. Both routes end in `TrustLevel.VERIFIED` through the
 * same trust policy.
 */
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
                    snackbarHostState.showSnackbar("Confirmed. This contact is now marked as checked in person.")
            }
        }
    }

    Scaffold(
        containerColor = QubeePalette.Void,
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            QubeeTopBar(
                title = stringResource(R.string.verify_title, state.contactName.ifBlank { "…" }),
                onBack = onClose,
            )
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
            text = stringResource(R.string.verify_load_error),
            color = QubeePalette.Text,
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(8.dp))
        QubeeMutedText(text = message)
        Spacer(Modifier.height(24.dp))
        QubeePrimaryButton(text = stringResource(R.string.verify_close), onClick = onClose)
    }
}

@Composable
@androidx.annotation.VisibleForTesting
internal fun VerifyContent(
    state: ContactVerificationUiState,
    onTypedFingerprintChange: (String) -> Unit,
    onConfirmFingerprint: () -> Unit,
    onConfirmSas: () -> Unit,
    onScanQr: () -> Unit,
) {
    var mismatch by remember { mutableStateOf(false) }
    val name = state.contactName.ifBlank { "this contact" }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(start = 24.dp, end = 24.dp, top = 4.dp, bottom = 28.dp),
    ) {
        QubeeMutedText(
            text = stringResource(R.string.verify_body),
            style = MaterialTheme.typography.bodyLarge,
        )

        Spacer(Modifier.height(20.dp))
        val sas = state.sasCode
        if (sas != null) {
            SasGrid(sas)
        } else {
            QubeeMutedText(stringResource(R.string.verify_no_code))
        }

        if (state.alreadyVerified) {
            Spacer(Modifier.height(16.dp))
            NoteCard(
                text = stringResource(R.string.verify_already, name),
                color = QubeePalette.Green,
                icon = Icons.Filled.GppGood,
            )
        }

        Spacer(Modifier.height(20.dp))
        QubeePrimaryButton(
            text = stringResource(R.string.verify_match),
            onClick = {
                mismatch = false
                onConfirmSas()
            },
            enabled = sas != null,
        )
        Spacer(Modifier.height(10.dp))
        QubeeDangerButton(
            text = stringResource(R.string.verify_mismatch),
            onClick = { mismatch = true },
            enabled = sas != null,
        )
        if (mismatch) {
            Spacer(Modifier.height(12.dp))
            NoteCard(
                text = stringResource(R.string.verify_mismatch_warning),
                color = QubeePalette.Warning,
                icon = Icons.Filled.GppMaybe,
            )
        }

        Spacer(Modifier.height(28.dp))
        QubeeSectionLabel(stringResource(R.string.verify_other_ways))
        Spacer(Modifier.height(12.dp))
        QubeeMutedText(
            stringResource(R.string.verify_their_fingerprint),
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = state.contactFingerprint.ifBlank { "Not available" },
            color = QubeePalette.Text,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = QubeeMono,
        )

        Spacer(Modifier.height(16.dp))
        QubeeTextField(
            value = state.typedFingerprint,
            onValueChange = onTypedFingerprintChange,
            label = stringResource(R.string.verify_typed_label, name),
            singleLine = false,
            monospace = true,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            QubeeSecondaryButton(
                text = stringResource(R.string.verify_scan),
                onClick = onScanQr,
                icon = Icons.Filled.QrCodeScanner,
                modifier = Modifier.weight(1f),
            )
            QubeeSecondaryButton(
                text = stringResource(R.string.verify_typed_button),
                onClick = onConfirmFingerprint,
                enabled = state.typedFingerprint.isNotBlank(),
                modifier = Modifier.weight(1f),
            )
        }

        if (state.myFingerprint != null) {
            Spacer(Modifier.height(24.dp))
            Text(
                stringResource(R.string.verify_let_them_scan),
                color = QubeePalette.Text,
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(4.dp))
            QubeeMutedText(
                stringResource(R.string.verify_let_them_scan_body),
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(12.dp))
            val bitmap = remember(state.myFingerprint) {
                QrUtils.encodeAsBitmap(state.myFingerprint, sizePx = 540)
            }
            QubeeQrCard(bitmap = bitmap, contentDescription = "Your verification code")
            Spacer(Modifier.height(8.dp))
            Text(
                text = state.myFingerprint,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
                fontFamily = QubeeMono,
                color = QubeePalette.MutedText,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/** The short code as large cards, two per row, in whatever groups Rust formatted it. */
@Composable
private fun SasGrid(sas: String) {
    val chunks = sas.split(Regex("[\\s-]+")).filter { it.isNotBlank() }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        chunks.chunked(2).forEachIndexed { rowIndex, pair ->
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                pair.forEachIndexed { column, chunk ->
                    SasCard(
                        index = rowIndex * 2 + column + 1,
                        text = chunk,
                        modifier = Modifier.weight(1f),
                    )
                }
                if (pair.size == 1) Spacer(Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun SasCard(index: Int, text: String, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        color = QubeePalette.Panel,
        border = BorderStroke(1.dp, QubeePalette.PanelAlt),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp)) {
            Text(
                text = index.toString(),
                color = QubeePalette.MutedText,
                style = MaterialTheme.typography.labelSmall,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text = text,
                color = QubeePalette.Text,
                style = MaterialTheme.typography.headlineSmall,
                fontFamily = QubeeMono,
            )
        }
    }
}

@Composable
private fun NoteCard(text: String, color: androidx.compose.ui.graphics.Color, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = QubeePalette.Panel,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(10.dp))
            QubeeMutedText(text, style = MaterialTheme.typography.bodySmall)
        }
    }
}
