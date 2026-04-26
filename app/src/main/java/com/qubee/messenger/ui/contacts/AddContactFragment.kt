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
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.identity.IdentityBundle
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
            setContent { AddContactScreen(viewModel, initialLink = link) }
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
) : ViewModel() {

    private val _state = MutableStateFlow(AddContactState())
    val state: StateFlow<AddContactState> = _state.asStateFlow()

    fun verify(link: String) {
        viewModelScope.launch {
            _state.value = AddContactState(isWorking = true)
            val json = qubeeManager.verifyOnboardingLink(link)
            val bundle = IdentityBundle.fromJson(json)
            _state.value = if (bundle != null) {
                AddContactState(bundle = bundle)
            } else {
                AddContactState(error = "Invalid or tampered identity link")
            }
        }
    }
}

data class AddContactState(
    val isWorking: Boolean = false,
    val bundle: IdentityBundle? = null,
    val error: String? = null,
)

@Composable
private fun AddContactScreen(
    viewModel: AddContactViewModel,
    initialLink: String?,
) {
    val state by viewModel.state.collectAsState()

    LaunchedEffect(initialLink) {
        if (!initialLink.isNullOrBlank() && QrUtils.isIdentityLink(initialLink)) {
            viewModel.verify(initialLink)
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Add contact", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))

        when {
            state.isWorking -> CircularProgressIndicator()
            state.error != null -> Text(state.error!!, color = MaterialTheme.colorScheme.error)
            state.bundle != null -> {
                val bundle = state.bundle!!
                Text(bundle.displayName, style = MaterialTheme.typography.titleLarge)
                Text("Fingerprint: ${bundle.fingerprint}")
                Spacer(Modifier.height(16.dp))
                val link = bundle.shareLink
                val bitmap = remember(link) { link?.let { QrUtils.encodeAsBitmap(it) } }
                bitmap?.let {
                    Image(
                        bitmap = it.asImageBitmap(),
                        contentDescription = "Identity QR",
                        modifier = Modifier.size(200.dp),
                    )
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { /* hook into ContactRepository.addContact when wired */ },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Save contact") }
            }
            else -> Text("Open a qubee://identity/... link to verify a contact.")
        }
    }
}
