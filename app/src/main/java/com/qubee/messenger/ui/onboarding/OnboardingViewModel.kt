package com.qubee.messenger.ui.onboarding

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.PreferenceRepository
import com.qubee.messenger.identity.IdentityBundle
import dagger.hilt.android.lifecycle.HiltViewModel
import java.util.UUID
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Drives the first-run flow. Generates a hybrid identity inside the Rust
 * core, captures the resulting [IdentityBundle] (public key + ZK proof
 * of ownership + share link), persists the public bits to encrypted
 * prefs, and surfaces the share link so the UI can render it as a QR
 * code for peer-to-peer key exchange.
 */
@HiltViewModel
class OnboardingViewModel @Inject constructor(
    private val qubeeManager: QubeeManager,
    private val preferences: PreferenceRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<OnboardingState>(
        if (preferences.isOnboarded()) OnboardingState.Complete else OnboardingState.Idle
    )
    val state = _state.asStateFlow()

    fun createIdentity(nickname: String) {
        if (nickname.isBlank()) return
        viewModelScope.launch {
            _state.value = OnboardingState.Loading

            // Make sure the Rust core is up before we cross the JNI boundary.
            val ready = qubeeManager.initialize()
            if (!ready) {
                _state.value = OnboardingState.Error("Could not initialise Qubee core")
                return@launch
            }

            val userId = preferences.userId() ?: UUID.randomUUID().toString()
            val json = qubeeManager.createOnboardingBundle(nickname.trim(), userId)
            val bundle = IdentityBundle.fromJson(json)
            if (bundle == null) {
                _state.value = OnboardingState.Error("Could not generate identity / ZK proof")
                return@launch
            }

            preferences.saveBundle(bundle)
            Timber.d("Onboarding complete for ${bundle.identityIdHex.take(8)}…")
            _state.value = OnboardingState.Success(
                bundle = bundle,
                storageEncrypted = preferences.isEncrypted,
            )
        }
    }

    fun acknowledge() {
        if (_state.value is OnboardingState.Success) {
            _state.value = OnboardingState.Complete
        }
    }
}

sealed class OnboardingState {
    object Idle : OnboardingState()
    object Loading : OnboardingState()
    /** Identity was just created — UI should show the QR for sharing. */
    data class Success(
        val bundle: IdentityBundle,
        /** False when EncryptedSharedPreferences fell back to plaintext. */
        val storageEncrypted: Boolean = true,
    ) : OnboardingState()
    /** Stable post-onboarding state; main UI should take over. */
    object Complete : OnboardingState()
    data class Error(val message: String) : OnboardingState()
}
