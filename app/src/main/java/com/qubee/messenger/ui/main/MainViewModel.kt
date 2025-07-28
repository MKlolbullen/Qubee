package com.qubee.messenger.ui.main

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.data.repository.ConversationRepository
import com.qubee.messenger.data.repository.ContactRepository
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

@HiltViewModel
class MainViewModel @Inject constructor(
    private val conversationRepository: ConversationRepository,
    private val contactRepository: ContactRepository,
    private val qubeeManager: QubeeManager
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
                
                // Initialize Qubee cryptographic system
                val cryptoInitialized = qubeeManager.initialize()
                if (!cryptoInitialized) {
                    throw Exception("Failed to initialize cryptographic system")
                }
                
                // Load initial data
                loadInitialData()
                
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    isInitialized = true
                )
                
                Timber.d("App initialization completed successfully")
                
            } catch (e: Exception) {
                Timber.e(e, "Failed to initialize app")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = e.message ?: "Unknown error occurred"
                )
            }
        }
    }

    private suspend fun loadInitialData() {
        // Load conversations and contacts
        // This will be implemented when we create the repositories
        Timber.d("Loading initial data...")
    }

    fun onPermissionsGranted() {
        viewModelScope.launch {
            try {
                // Permissions granted, continue with initialization
                if (!_uiState.value.isInitialized) {
                    initializeApp()
                }
            } catch (e: Exception) {
                Timber.e(e, "Error after permissions granted")
                _uiState.value = _uiState.value.copy(
                    error = e.message ?: "Error initializing after permissions"
                )
            }
        }
    }

    fun onConversationClicked(contactId: String) {
        viewModelScope.launch {
            _navigationEvents.emit(NavigationEvent.OpenChat(contactId))
        }
    }

    fun onSettingsClicked() {
        viewModelScope.launch {
            _navigationEvents.emit(NavigationEvent.OpenSettings)
        }
    }

    fun onNewChatClicked() {
        viewModelScope.launch {
            _navigationEvents.emit(NavigationEvent.OpenContactSelection)
        }
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    data class MainUiState(
        val isLoading: Boolean = false,
        val isInitialized: Boolean = false,
        val error: String? = null
    )

    sealed class NavigationEvent {
        data class OpenChat(val contactId: String) : NavigationEvent()
        object OpenSettings : NavigationEvent()
        object OpenContactSelection : NavigationEvent()
    }
}

