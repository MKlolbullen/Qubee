package com.qubee.messenger.ui.contacts

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.ui.theme.QubeeAvatar
import com.qubee.messenger.ui.theme.QubeeMono
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePanel
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeScreen
import com.qubee.messenger.ui.theme.QubeeSectionLabel
import com.qubee.messenger.ui.theme.QubeeStatusPill
import com.qubee.messenger.ui.theme.QubeeTheme
import com.qubee.messenger.ui.theme.QubeeTopBar
import com.qubee.messenger.ui.theme.QubeeTrust
import com.qubee.messenger.ui.theme.label
import com.qubee.messenger.ui.theme.qubeeInitials
import com.qubee.messenger.util.QrUtils
import dagger.hilt.android.AndroidEntryPoint
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Lands users here when a peer sends them a `qubee://identity/<token>`
 * link (or after they scan one). Verifies the embedded hybrid
 * Ed25519+Dilithium signature via the Rust core and previews the
 * contact before they save it. Saving opens the new chat.
 */
@AndroidEntryPoint
class AddContactFragment : Fragment() {

    private val viewModel: AddContactViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // The scanner on the Add someone screen passes the link as an
        // argument; a tapped qubee://identity/... link arrives as the
        // deep-link intent Navigation stores under KEY_DEEP_LINK_INTENT.
        val link = arguments?.getString("link") ?: deepLinkUri()
        return ComposeView(requireContext()).apply {
            setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
            setContent {
                val state by viewModel.state.collectAsStateWithLifecycle()
                LaunchedEffect(link) {
                    if (!link.isNullOrBlank() && QrUtils.isIdentityLink(link)) viewModel.verify(link)
                }
                LaunchedEffect(state.savedContactId) {
                    val contactId = state.savedContactId ?: return@LaunchedEffect
                    findNavController().navigate(
                        R.id.action_add_contact_to_chat,
                        Bundle().apply { putString("contactId", contactId) },
                    )
                }
                QubeeTheme {
                    QubeeScreen {
                        AddContactBody(
                            state = state,
                            onBack = { findNavController().navigateUp() },
                            onSave = viewModel::save,
                            onScan = { findNavController().navigate(R.id.action_add_contact_to_connect) },
                        )
                    }
                }
            }
        }
    }

    private fun deepLinkUri(): String? {
        val intent: Intent? = arguments?.getParcelable(NavController.KEY_DEEP_LINK_INTENT)
        return intent?.data?.toString()
    }
}

@HiltViewModel
class AddContactViewModel @Inject constructor(
    private val qubeeManager: QubeeManager,
    private val contactRepository: ContactRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(AddContactState())
    val state: StateFlow<AddContactState> = _state.asStateFlow()

    fun verify(link: String) {
        viewModelScope.launch {
            _state.value = AddContactState(isWorking = true, link = link)
            val json = qubeeManager.verifyOnboardingLink(link)
            val bundle = IdentityBundle.fromJson(json)
            _state.value = if (bundle != null) {
                AddContactState(bundle = bundle, link = link)
            } else {
                AddContactState(error = AddContactError.InvalidLink)
            }
        }
    }

    /** Re-verifies the link through the Rust core and stores the contact; the stored row's id opens the chat. */
    fun save() {
        val current = _state.value
        val link = current.link ?: return
        if (current.isSaving || current.savedContactId != null) return
        viewModelScope.launch {
            _state.value = current.copy(isSaving = true, error = null)
            val contact = runCatching { contactRepository.addContactFromInviteLink(link) }.getOrNull()
            _state.value = if (contact != null) {
                _state.value.copy(isSaving = false, savedContactId = contact.id)
            } else {
                _state.value.copy(isSaving = false, error = AddContactError.SaveFailed)
            }
        }
    }
}

enum class AddContactError { InvalidLink, SaveFailed }

data class AddContactState(
    val isWorking: Boolean = false,
    val link: String? = null,
    val bundle: IdentityBundle? = null,
    val error: AddContactError? = null,
    val isSaving: Boolean = false,
    val savedContactId: String? = null,
)

/** Stateless render of the Add contact screen, exposed for Paparazzi. */
@Composable
@androidx.annotation.VisibleForTesting
internal fun AddContactBody(
    state: AddContactState,
    onBack: () -> Unit,
    onSave: () -> Unit,
    onScan: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        QubeeTopBar(title = stringResource(R.string.add_contact_title), onBack = onBack)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(start = 24.dp, end = 24.dp, top = 8.dp, bottom = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            val bundle = state.bundle
            when {
                state.isWorking -> {
                    Spacer(Modifier.height(48.dp))
                    CircularProgressIndicator(color = QubeePalette.Cyan)
                    Spacer(Modifier.height(16.dp))
                    QubeeMutedText(stringResource(R.string.add_contact_checking))
                }
                state.error == AddContactError.InvalidLink -> {
                    Spacer(Modifier.height(24.dp))
                    QubeeAvatar(initials = "", size = 72.dp, icon = Icons.Filled.GppBad, color = QubeePalette.Danger)
                    Spacer(Modifier.height(18.dp))
                    Text(
                        text = stringResource(R.string.add_contact_invalid),
                        color = QubeePalette.MutedText,
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(24.dp))
                    QubeePrimaryButton(
                        text = stringResource(R.string.add_contact_scan_again),
                        onClick = onScan,
                        icon = Icons.Filled.QrCodeScanner,
                    )
                }
                bundle != null -> ContactPreview(
                    bundle = bundle,
                    saving = state.isSaving,
                    saveFailed = state.error == AddContactError.SaveFailed,
                    onSave = onSave,
                )
                else -> {
                    Spacer(Modifier.height(24.dp))
                    Text(
                        text = stringResource(R.string.add_contact_no_link),
                        color = QubeePalette.MutedText,
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(24.dp))
                    QubeePrimaryButton(
                        text = stringResource(R.string.add_contact_scan),
                        onClick = onScan,
                        icon = Icons.Filled.QrCodeScanner,
                    )
                }
            }
        }
    }
}

@Composable
private fun ContactPreview(
    bundle: IdentityBundle,
    saving: Boolean,
    saveFailed: Boolean,
    onSave: () -> Unit,
) {
    val name = bundle.displayName.ifBlank { bundle.identityIdHex.take(8) }
    Spacer(Modifier.height(16.dp))
    QubeeAvatar(initials = name.qubeeInitials(), size = 84.dp)
    Spacer(Modifier.height(16.dp))
    Text(
        text = name,
        color = QubeePalette.Text,
        style = MaterialTheme.typography.headlineMedium,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(10.dp))
    QubeeStatusPill(text = QubeeTrust.Unverified.label(), color = QubeePalette.MutedText)
    Spacer(Modifier.height(24.dp))
    QubeePanel {
        QubeeSectionLabel(stringResource(R.string.add_contact_fingerprint))
        Spacer(Modifier.height(8.dp))
        Text(
            text = bundle.fingerprint,
            color = QubeePalette.Text,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = QubeeMono,
        )
    }
    Spacer(Modifier.height(16.dp))
    Text(
        text = stringResource(R.string.add_contact_body, name),
        color = QubeePalette.MutedText,
        style = MaterialTheme.typography.bodyMedium,
        textAlign = TextAlign.Center,
    )
    if (saveFailed) {
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.GppBad, contentDescription = null, tint = QubeePalette.Danger, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.add_contact_save_failed),
                color = QubeePalette.Danger,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    Spacer(Modifier.height(24.dp))
    QubeePrimaryButton(
        text = stringResource(if (saving) R.string.add_contact_saving else R.string.add_contact_save),
        onClick = onSave,
        enabled = !saving,
    )
}
