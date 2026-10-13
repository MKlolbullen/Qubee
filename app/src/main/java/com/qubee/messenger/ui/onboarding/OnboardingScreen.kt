package com.qubee.messenger.ui.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.qubee.messenger.R
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.ui.connect.shareIdentityLink
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeHeroMark
import com.qubee.messenger.ui.theme.QubeeMono
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeQrCard
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSecondaryButton
import com.qubee.messenger.ui.theme.QubeeTextField
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.util.QrUtils

@Composable
fun OnboardingScreen(
    viewModel: OnboardingViewModel,
    onOnboardingComplete: () -> Unit,
) {
    QubeeTheme {
        val state by viewModel.state.collectAsStateWithLifecycle()
        var nickname by remember { mutableStateOf("") }

        LaunchedEffect(state) {
            if (state is OnboardingState.Complete) onOnboardingComplete()
        }

        QubeeScreen {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 24.dp, vertical = 28.dp),
            ) {
                when (val s = state) {
                    is OnboardingState.Success -> SuccessView(
                        bundle = s.bundle,
                        onDone = {
                            viewModel.acknowledge()
                            onOnboardingComplete()
                        },
                    )

                    // Complete state: nothing to render — the LaunchedEffect above
                    // takes care of navigation as soon as we land here.
                    OnboardingState.Complete -> Unit

                    else -> IdentityBootstrapView(
                        state = s,
                        nickname = nickname,
                        onNicknameChange = { nickname = it },
                        onCreate = { viewModel.createIdentity(nickname.trim()) },
                    )
                }
            }
        }
    }
}

/**
 * The welcome screen body. A column-scope extension so the primary
 * button can take the remaining height and sit at the bottom on a
 * tall screen while the whole thing still scrolls on a short one.
 */
@Composable
@androidx.annotation.VisibleForTesting
internal fun ColumnScope.IdentityBootstrapView(
    state: OnboardingState,
    nickname: String,
    onNicknameChange: (String) -> Unit,
    onCreate: () -> Unit,
) {
    val loading = state is OnboardingState.Loading

    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
        QubeeHeroMark(width = 200.dp)
    }
    Spacer(Modifier.height(20.dp))

    Text(
        stringResource(R.string.welcome_title),
        color = QubeePalette.Text,
        style = MaterialTheme.typography.headlineLarge,
    )
    Spacer(Modifier.height(12.dp))
    QubeeMutedText(
        stringResource(R.string.welcome_body),
        style = MaterialTheme.typography.bodyLarge,
    )

    Spacer(Modifier.height(24.dp))
    FeatureRow(Icons.Outlined.Lock, stringResource(R.string.welcome_feature_pq))
    Spacer(Modifier.height(12.dp))
    FeatureRow(Icons.Outlined.Wifi, stringResource(R.string.welcome_feature_lan))
    Spacer(Modifier.height(12.dp))
    FeatureRow(Icons.Filled.GppGood, stringResource(R.string.welcome_feature_verify))

    Spacer(Modifier.height(28.dp))
    Text(
        stringResource(R.string.welcome_name_label),
        color = QubeePalette.MutedText,
        style = MaterialTheme.typography.labelMedium,
    )
    Spacer(Modifier.height(8.dp))
    QubeeTextField(
        value = nickname,
        onValueChange = onNicknameChange,
        placeholder = stringResource(R.string.welcome_name_placeholder),
        enabled = !loading,
    )
    Spacer(Modifier.height(8.dp))
    QubeeMutedText(
        stringResource(R.string.welcome_name_hint),
        style = MaterialTheme.typography.bodySmall,
    )
    if (state is OnboardingState.Error) {
        Spacer(Modifier.height(12.dp))
        Text(
            state.message,
            color = QubeePalette.Danger,
            style = MaterialTheme.typography.bodySmall,
        )
    }

    Spacer(Modifier.weight(1f))
    Spacer(Modifier.height(24.dp))

    if (loading) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(54.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            CircularProgressIndicator(color = QubeePalette.Cyan, modifier = Modifier.size(24.dp))
            Spacer(Modifier.width(12.dp))
            QubeeMutedText(stringResource(R.string.welcome_generating))
        }
    } else {
        QubeePrimaryButton(
            text = stringResource(R.string.welcome_create),
            onClick = onCreate,
            enabled = nickname.isNotBlank(),
        )
    }
    Spacer(Modifier.height(14.dp))
    Text(
        stringResource(R.string.welcome_footnote),
        modifier = Modifier.fillMaxWidth(),
        color = QubeePalette.MutedText,
        style = MaterialTheme.typography.bodySmall,
        textAlign = TextAlign.Center,
    )
}

@Composable
private fun FeatureRow(icon: ImageVector, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        QubeeAvatar(initials = "", size = 36.dp, icon = icon)
        Spacer(Modifier.width(12.dp))
        Text(text, color = QubeePalette.Text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun SuccessView(
    bundle: IdentityBundle,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    val link = bundle.shareLink
    val bitmap = remember(link) { link?.let { QrUtils.encodeAsBitmap(it, sizePx = 540) } }

    Spacer(Modifier.height(8.dp))
    Text(
        stringResource(R.string.identity_ready_title),
        color = QubeePalette.Text,
        style = MaterialTheme.typography.headlineLarge,
    )
    Spacer(Modifier.height(6.dp))
    Text(
        bundle.displayName,
        color = QubeePalette.Cyan,
        style = MaterialTheme.typography.titleLarge,
    )
    Spacer(Modifier.height(12.dp))
    QubeeMutedText(
        stringResource(R.string.identity_ready_body),
        style = MaterialTheme.typography.bodyLarge,
    )

    Spacer(Modifier.height(24.dp))
    QubeeQrCard(
        bitmap = bitmap,
        contentDescription = stringResource(R.string.connect_qr_description),
        title = stringResource(R.string.connect_qr_title),
        body = stringResource(R.string.connect_qr_body),
    )

    Spacer(Modifier.height(20.dp))
    Text(
        stringResource(R.string.identity_fingerprint),
        color = QubeePalette.MutedText,
        style = MaterialTheme.typography.labelMedium,
    )
    Spacer(Modifier.height(4.dp))
    Text(
        bundle.fingerprint,
        color = QubeePalette.Text,
        style = MaterialTheme.typography.bodyMedium,
        fontFamily = QubeeMono,
    )

    Spacer(Modifier.height(24.dp))
    if (link != null) {
        QubeeSecondaryButton(
            text = stringResource(R.string.identity_share_link),
            onClick = { shareIdentityLink(context, link) },
        )
        Spacer(Modifier.height(10.dp))
    }
    QubeePrimaryButton(text = stringResource(R.string.identity_continue), onClick = onDone)
}
