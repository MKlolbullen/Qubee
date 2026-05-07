package com.qubee.messenger.ui.contacts.verification

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.data.repository.ContactRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives `ContactVerificationActivity` / `VerifyContactScreen`.
 *
 * Loads the contact's stored `IdentityKey`, asks the Rust core for
 * its 8-byte BLAKE3 fingerprint and the symmetric SAS code shared
 * with the local user, then exposes the two confirm gestures — typed
 * fingerprint match, or visual SAS match — that flip the contact's
 * `TrustLevel` to `VERIFIED` and `ContactVerificationStatus` to
 * `VERIFIED` and persist via the repository.
 *
 * The activity passes `identityIdHex` as a SavedStateHandle key.
 * Resolving back to a Contact row uses
 * [ContactRepository.getContactByIdentityId]; if the contact has
 * been deleted in another session the screen renders an empty
 * state and disables the confirm buttons.
 */
@HiltViewModel
class ContactVerificationViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val contactRepository: ContactRepository,
    private val qubeeManager: QubeeManager,
) : ViewModel() {

    private val identityIdHex: String =
        savedStateHandle[ContactVerificationActivity.EXTRA_IDENTITY_ID] ?: ""

    private val _uiState = MutableStateFlow(ContactVerificationUiState())
    val uiState: StateFlow<ContactVerificationUiState> = _uiState.asStateFlow()

    private val _events = MutableSharedFlow<ContactVerificationEvent>(extraBufferCapacity = 4)
    val events: SharedFlow<ContactVerificationEvent> = _events.asSharedFlow()

    private var contact: Contact? = null

    init {
        viewModelScope.launch {
            val resolved = contactRepository.getContactByIdentityId(identityIdHex)
            contact = resolved
            if (resolved == null) {
                _uiState.value = _uiState.value.copy(
                    loadError = "Contact not found in local address book.",
                    isLoading = false,
                )
                return@launch
            }
            val key = resolved.identityKey
            val contactFingerprint = key?.let { qubeeManager.computeFingerprint(it) }
                ?: ""
            val myFingerprint = qubeeManager.getMyFingerprint()
            val sas = key?.let { qubeeManager.generateSASForContact(it) }
            val alreadyVerified = resolved.trustLevel == TrustLevel.VERIFIED
            _uiState.value = ContactVerificationUiState(
                contactName = resolved.displayName.ifBlank { "Unnamed contact" },
                contactFingerprint = contactFingerprint,
                myFingerprint = myFingerprint,
                sasCode = sas,
                alreadyVerified = alreadyVerified,
                isLoading = false,
            )
        }
    }

    /** Stash the typed-or-scanned fingerprint as the user enters it. */
    fun onTypedFingerprintChange(value: String) {
        _uiState.value = _uiState.value.copy(typedFingerprint = value)
    }

    /**
     * Compare the typed fingerprint to the contact's stored
     * `IdentityKey` via the Rust `verifyIdentityKey` JNI export
     * (which normalises whitespace + case). On match, persist the
     * `VERIFIED` flag; on mismatch, surface a notice so the user
     * can retry without losing the typed value.
     */
    fun confirmFingerprintMatch() {
        val target = contact ?: return
        val key = target.identityKey ?: run {
            viewModelScope.launch {
                _events.emit(ContactVerificationEvent.Notice("Contact has no stored identity key."))
            }
            return
        }
        val typed = _uiState.value.typedFingerprint.trim()
        if (typed.isBlank()) return
        viewModelScope.launch {
            val ok = qubeeManager.verifyIdentityKey(
                contactId = target.id,
                identityKey = key,
                verificationData = typed.toByteArray(Charsets.UTF_8),
            )
            if (ok) {
                persistVerified(target)
                _events.emit(ContactVerificationEvent.Verified)
            } else {
                _events.emit(
                    ContactVerificationEvent.Notice(
                        "Fingerprint doesn't match — re-read carefully and try again.",
                    ),
                )
            }
        }
    }

    /**
     * The user attests that the SAS code on both devices matches.
     * No bridge round-trip — the user's claim of a visual match
     * IS the trust ceremony. Persist the `VERIFIED` flag.
     */
    fun confirmSasMatch() {
        val target = contact ?: return
        viewModelScope.launch {
            persistVerified(target)
            _events.emit(ContactVerificationEvent.Verified)
        }
    }

    /**
     * Inject a scanned QR string (e.g. from `QrScannerActivity`)
     * straight into [confirmFingerprintMatch]. Same bridge path
     * as the typed value.
     */
    fun onQrScanned(payload: String) {
        _uiState.value = _uiState.value.copy(typedFingerprint = payload)
        confirmFingerprintMatch()
    }

    private suspend fun persistVerified(target: Contact) {
        contactRepository.updateTrustLevel(target.id, TrustLevel.VERIFIED)
        contactRepository.updateVerificationStatus(target.id, ContactVerificationStatus.VERIFIED)
        _uiState.value = _uiState.value.copy(alreadyVerified = true)
    }
}

data class ContactVerificationUiState(
    val isLoading: Boolean = true,
    val contactName: String = "",
    val contactFingerprint: String = "",
    val myFingerprint: String? = null,
    val sasCode: String? = null,
    val typedFingerprint: String = "",
    val alreadyVerified: Boolean = false,
    val loadError: String? = null,
)

sealed class ContactVerificationEvent {
    data class Notice(val message: String) : ContactVerificationEvent()
    object Verified : ContactVerificationEvent()
}
