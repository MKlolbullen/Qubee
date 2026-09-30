package com.qubee.messenger.ui.contacts

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.ui.theme.QubeeMutedText
import com.qubee.messenger.ui.theme.QubeePalette
import com.qubee.messenger.ui.theme.QubeePrimaryButton
import com.qubee.messenger.ui.theme.QubeeTheme
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
 * contact before they accept.
 */
@AndroidEntryPoint
class AddContactFragment : Fragment() {

    private val viewModel: AddContactViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // Pull the full `qubee://identity/...` URI off the deep-link
        // intent that Navigation hands us via KEY_DEEP_LINK_INTENT.
        val link = deepLinkUri()
        return ComposeView(requireContext()).apply {
            setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
            setContent {
                AddContactScreen(viewModel, initialLink = link, onSaved = ::openChat)
            }
        }
    }

    /** Land in the new contact's chat, dropping this screen from the back stack. */
    private fun openChat(contactId: String) {
        val nav = findNavController()
        nav.navigate(
            R.id.chatFragment,
            Bundle().apply { putString("contactId", contactId) },
            NavOptions.Builder()
                .setPopUpTo(R.id.addContactFragment, /* inclusive = */ true)
                .build(),
        )
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

    private var verifiedLink: String? = null

    fun verify(link: String) {
        viewModelScope.launch {
            _state.value = AddContactState(isWorking = true)
            val json = qubeeManager.verifyOnboardingLink(link)
            val bundle = IdentityBundle.fromJson(json)
            _state.value = if (bundle != null) {
                verifiedLink = link
                AddContactState(bundle = bundle)
            } else {
                verifiedLink = null
                AddContactState(error = "Invalid or tampered identity link")
            }
        }
    }

    /**
     * Persist the verified identity as a Contact (re-verifying the link
     * inside the repository, which is the single write path for
     * link-sourced contacts) and hand the new row id to the UI.
     */
    fun save() {
        val link = verifiedLink ?: return
        val bundle = _state.value.bundle ?: return
        viewModelScope.launch {
            _state.value = AddContactState(bundle = bundle, isWorking = true)
            val contact = contactRepository.addContactFromInviteLink(link)
            _state.value = if (contact != null) {
                AddContactState(bundle = bundle, savedContactId = contact.id)
            } else {
                AddContactState(bundle = bundle, error = "Couldn't save the contact — try scanning again")
            }
        }
    }

    fun consumeSaved() {
        _state.value = _state.value.copy(savedContactId = null)
    }
}

data class AddContactState(
    val isWorking: Boolean = false,
    val bundle: IdentityBundle? = null,
    val error: String? = null,
    val savedContactId: String? = null,
)

@Composable
private fun AddContactScreen(
    viewModel: AddContactViewModel,
    initialLink: String?,
    onSaved: (String) -> Unit,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    LaunchedEffect(initialLink) {
        if (!initialLink.isNullOrBlank() && QrUtils.isIdentityLink(initialLink)) {
            viewModel.verify(initialLink)
        }
    }

    LaunchedEffect(state.savedContactId) {
        state.savedContactId?.let { id ->
            viewModel.consumeSaved()
            onSaved(id)
        }
    }

    // Flat Void ground rather than `QubeeScreen` — this surface sits
    // in the same family as the verify screen, which drops the grid
    // and radial wash so the scanned-identity payload is the only
    // thing on the page.
    QubeeTheme {
        Surface(color = QubeePalette.Void, modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Top,
            ) {
                Text(
                    "Add contact",
                    color = QubeePalette.Text,
                    style = MaterialTheme.typography.headlineSmall,
                )
                Spacer(Modifier.height(16.dp))

                when {
                    state.isWorking -> CircularProgressIndicator(color = QubeePalette.Cyan)
                    state.error != null -> Text(
                        state.error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                    state.bundle != null -> {
                        val bundle = state.bundle!!
                        Text(
                            bundle.displayName,
                            color = QubeePalette.Text,
                            style = MaterialTheme.typography.titleLarge,
                        )
                        Spacer(Modifier.height(4.dp))
                        QubeeMutedText("Fingerprint")
                        Text(
                            bundle.fingerprint,
                            color = QubeePalette.Text,
                            style = MaterialTheme.typography.bodyLarge,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Spacer(Modifier.height(16.dp))
                        val link = bundle.shareLink
                        val bitmap = remember(link) { link?.let { QrUtils.encodeAsBitmap(it) } }
                        bitmap?.let {
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = QubeePalette.Text,
                            ) {
                                Image(
                                    bitmap = it.asImageBitmap(),
                                    contentDescription = "Identity QR",
                                    modifier = Modifier.padding(12.dp).size(200.dp),
                                )
                            }
                        }
                        Spacer(Modifier.height(16.dp))
                        QubeePrimaryButton(
                            text = "Save contact",
                            onClick = viewModel::save,
                        )
                    }
                    else -> Text(
                        "Open a qubee://identity/... link to verify a contact.",
                        color = QubeePalette.Text,
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}
