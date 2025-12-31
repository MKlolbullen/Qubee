package com.qubee.messenger.ui.onboarding

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.PreferenceRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

@HiltViewModel
class OnboardingViewModel @Inject constructor(
    private val qubeeManager: QubeeManager,
    private val preferences: PreferenceRepository // Antagen repository för SharedPreferences
) : ViewModel() {

    private val _state = MutableStateFlow<OnboardingState>(OnboardingState.Idle)
    val state = _state.asStateFlow()

    fun createIdentity(nickname: String) {
        viewModelScope.launch {
            _state.value = OnboardingState.Loading

            // 1. Generera ett helt slumpmässigt ID (P2P-vänligt, kräver ingen server för att kolla unika namn)
            val randomId = UUID.randomUUID().toString()

            // 2. Generera kryptografiska nycklar via Rust (Kyber/Dilithium)
            val identityKeyPair = qubeeManager.generateIdentityKeyPair()

            if (identityKeyPair != null) {
                // 3. Spara allt lokalt
                preferences.saveUserIdentity(
                    userId = randomId,
                    nickname = nickname,
                    publicKey = identityKeyPair.publicKey
                )
                
                // Initiera P2P-nätverket med vår nya identitet
                // p2pManager.startNode(randomId) 

                _state.value = OnboardingState.Success
            } else {
                _state.value = OnboardingState.Error("Kunde inte generera kryptonycklar")
            }
        }
    }
}

sealed class OnboardingState {
    object Idle : OnboardingState()
    object Loading : OnboardingState()
    object Success : OnboardingState()
    data class Error(val message: String) : OnboardingState()
}
