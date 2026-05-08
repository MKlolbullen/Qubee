package com.qubee.messenger.ui.contacts

import android.content.Intent
import android.os.Bundle
import android.util.Base64
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
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.ContactRepository
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.util.QrUtils
import dagger.hilt.android.AndroidEntryPoint
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber

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
    private val contactRepository: ContactRepository,
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

    /**
     * Persist the verified contact and, if the bundle includes a
     * DM prekey, kick off an X3DH-style handshake. The handshake
     * init bytes go into [AddContactState.handshakeInitBytes] so
     * the UI can either auto-deliver them via P2P (once that
     * channel exists) or surface them for the user to share via
     * another medium.
     *
     * Outbound only: the receiver-side delivery path
     * (recognising an inbound handshake init off the gossipsub
     * topic and calling `qubeeManager.respondToDmHandshake`) is
     * a separate piece of plumbing that hasn't landed yet.
     */
    fun acceptContact() {
        val current = _state.value.bundle ?: return
        viewModelScope.launch {
            _state.value = _state.value.copy(isWorking = true, error = null)

            // Persist the contact row first. Reuse the peer's
            // identityIdHex as the local primary key so the
            // ChatViewModel's `contactId` route maps cleanly.
            val contact = Contact(
                id = current.identityIdHex,
                identityId = current.identityIdHex,
                displayName = current.displayName,
                trustLevel = TrustLevel.UNKNOWN,
                verificationStatus = ContactVerificationStatus.UNVERIFIED,
            )
            runCatching { contactRepository.addContact(contact) }
                .onFailure { e ->
                    Timber.e(e, "addContact failed")
                    _state.value = _state.value.copy(
                        isWorking = false,
                        error = "Couldn't save contact: ${e.message}",
                    )
                    return@launch
                }

            // Try to open a DM session if the bundle carries a
            // prekey bundle. Older v2 bundles (or v3 ones from
            // identity records that pre-date the create-time
            // prekey persistence) will have null here — skip the
            // handshake and the conversation falls back to the
            // group-message path until the contact owner re-shares
            // a v3 QR.
            val handshakeBytes: ByteArray? = current.dmPrekeyBundleB64?.let { b64 ->
                val peerBundle = runCatching {
                    Base64.decode(b64, Base64.DEFAULT)
                }.getOrNull() ?: run {
                    Timber.w("Couldn't base64-decode dm_prekey_bundle_b64")
                    return@let null
                }
                runCatching { qubeeManager.initiateDmHandshake(peerBundle) }
                    .onFailure { Timber.w(it, "initiateDmHandshake failed") }
                    .getOrNull()
            }

            _state.value = _state.value.copy(
                isWorking = false,
                saved = true,
                handshakeInitBytes = handshakeBytes,
            )
        }
    }
}

data class AddContactState(
    val isWorking: Boolean = false,
    val bundle: IdentityBundle? = null,
    val error: String? = null,
    val saved: Boolean = false,
    /// Wire bytes of a `DmHandshakeInit` for the peer to consume
    /// via `nativeRespondToDmHandshake`. Null when the peer's
    /// bundle didn't carry a DM prekey or when the handshake
    /// failed; in that case the UI falls back to "contact saved
    /// without secure DM" messaging.
    val handshakeInitBytes: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AddContactState) return false
        return isWorking == other.isWorking &&
            bundle == other.bundle &&
            error == other.error &&
            saved == other.saved &&
            handshakeInitBytes.contentEqualsNullable(other.handshakeInitBytes)
    }

    override fun hashCode(): Int {
        var result = isWorking.hashCode()
        result = 31 * result + (bundle?.hashCode() ?: 0)
        result = 31 * result + (error?.hashCode() ?: 0)
        result = 31 * result + saved.hashCode()
        result = 31 * result + (handshakeInitBytes?.contentHashCode() ?: 0)
        return result
    }
}

private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean = when {
    this == null && other == null -> true
    this == null || other == null -> false
    else -> this.contentEquals(other)
}

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

                if (state.saved) {
                    val msg = if (state.handshakeInitBytes != null) {
                        // Forward-secret + post-quantum-secure
                        // session is now half-established locally.
                        // Receiver-side delivery of these bytes is
                        // a separate piece of plumbing; for now we
                        // surface a status line.
                        "Contact saved. Secure DM session opened (handshake init " +
                            "${state.handshakeInitBytes!!.size} bytes pending peer delivery)."
                    } else if (bundle.dmPrekeyBundleB64 == null) {
                        "Contact saved. Older identity bundle — secure DM not " +
                            "available until the peer publishes a v3 QR."
                    } else {
                        "Contact saved. Secure DM handshake didn't open " +
                            "(see logs); messages will use the group-fallback path."
                    }
                    Text(msg, style = MaterialTheme.typography.bodyMedium)
                } else {
                    Button(
                        onClick = { viewModel.acceptContact() },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Save contact") }
                }
            }
            else -> Text("Open a qubee://identity/... link to verify a contact.")
        }
    }
}
