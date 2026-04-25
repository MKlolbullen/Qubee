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

    private val _state = MutableStateFlow<OnboardingState>(OnboardingState.Idle)
    val state = _state.asStateFlow()

    init {
        // On every launch, ask the Rust core whether it already has a
        // persisted identity. If yes, jump straight to Complete so the
        // app surface routes past the onboarding screen. If no, stay
        // on Idle and wait for the user to enter a display name.
        viewModelScope.launch {
            if (qubeeManager.initialize()) {
                val json = qubeeManager.loadOnboardingBundle()
                IdentityBundle.fromJson(json)?.let { bundle ->
                    preferences.saveBundle(bundle)
                    Timber.d("Restored persisted identity ${bundle.identityIdHex.take(8)}…")
                    _state.value = OnboardingState.Complete
                }
            }
        }
    }

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
                _state.value = OnboardingState.Error("Could not generate identity")
                return@launch
            }

            preferences.saveBundle(bundle)
            Timber.d("Onboarding complete for ${bundle.identityIdHex.take(8)}…")
            _state.value = OnboardingState.Success(bundle = bundle)
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
    data class Success(val bundle: IdentityBundle) : OnboardingState()
    /** Stable post-onboarding state; main UI should take over. */
    object Complete : OnboardingState()
    data class Error(val message: String) : OnboardingState()
}
