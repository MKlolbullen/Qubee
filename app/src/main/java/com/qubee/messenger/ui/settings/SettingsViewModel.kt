package com.qubee.messenger.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.PreferenceRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Drives Settings actions. Today only one: wiping the identity. Both
 * the JNI keystore and the Kotlin-side EncryptedSharedPreferences are
 * cleared so [PreferenceRepository.isOnboarded] returns false on the
 * next launch and MainActivity routes through onboarding again.
 */
@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val qubeeManager: QubeeManager,
    private val preferences: PreferenceRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<SettingsResetState>(SettingsResetState.Idle)
    val state: StateFlow<SettingsResetState> = _state.asStateFlow()

    fun resetIdentity() {
        viewModelScope.launch {
            _state.value = SettingsResetState.Working
            val ok = try {
                qubeeManager.resetIdentity()
            } catch (e: Exception) {
                Timber.e(e, "resetIdentity threw")
                false
            }
            if (ok) {
                // Wipe Kotlin-side prefs only after the JNI confirms
                // the keystore is gone, so a partial failure leaves
                // both stores aligned ("we still think we're onboarded
                // because the keys are still there").
                preferences.clearAll()
                _state.value = SettingsResetState.Done
            } else {
                _state.value = SettingsResetState.Error(
                    "Couldn't wipe the local keystore — try again, or " +
                        "uninstall and reinstall the app.",
                )
            }
        }
    }

    /**
     * After the SettingsFragment routes back to onboarding, drop the
     * Done state so a recomposition doesn't re-trigger navigation.
     */
    fun acknowledgeReset() {
        if (_state.value is SettingsResetState.Done) {
            _state.value = SettingsResetState.Idle
        }
    }
}

sealed class SettingsResetState {
    object Idle : SettingsResetState()
    object Working : SettingsResetState()
    object Done : SettingsResetState()
    data class Error(val message: String) : SettingsResetState()
}
