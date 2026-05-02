package com.qubee.messenger.ui.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

// Slimmed down to what MainActivity actually consumes today —
// initialization status + a navigation event channel. The original
// version constructor-injected ContactRepository / ConversationRepository
// to load aspirational dashboards that don't exist yet.

@HiltViewModel
class MainViewModel @Inject constructor(
    private val qubeeManager: QubeeManager,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    private val _navigationEvents = MutableSharedFlow<NavigationEvent>()
    val navigationEvents: SharedFlow<NavigationEvent> = _navigationEvents.asSharedFlow()

    init {
        initializeApp()
    }

    private fun initializeApp() {
        viewModelScope.launch {
            try {
                _uiState.value = _uiState.value.copy(isLoading = true)
                val ok = qubeeManager.initialize()
                if (!ok) throw IllegalStateException("Failed to initialize cryptographic system")
                _uiState.value = _uiState.value.copy(isLoading = false, isInitialized = true)
                Timber.d("App initialization completed successfully")
            } catch (e: Exception) {
                Timber.e(e, "Failed to initialize app")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = e.message ?: "Unknown error occurred",
                )
            }
        }
    }

    fun onPermissionsGranted() {
        viewModelScope.launch {
            if (!_uiState.value.isInitialized) initializeApp()
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    data class MainUiState(
        val isLoading: Boolean = false,
        val isInitialized: Boolean = false,
        val error: String? = null,
    )

    sealed class NavigationEvent {
        data class OpenChat(val contactId: String) : NavigationEvent()
        object OpenSettings : NavigationEvent()
        object OpenContactSelection : NavigationEvent()
    }
}
