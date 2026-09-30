package com.qubee.messenger.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.PreferenceRepository
import android.content.Context
import androidx.biometric.BiometricManager
import com.qubee.messenger.identity.IdentityBundle
import com.qubee.messenger.network.NodeAddresses
import com.qubee.messenger.security.AppLockManager
import com.qubee.messenger.security.DatabaseKeyHolder
import com.qubee.messenger.security.SqlCipherKeyProvider
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
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
    @ApplicationContext private val context: Context,
    private val qubeeManager: QubeeManager,
    private val preferences: PreferenceRepository,
    private val appLockManager: AppLockManager,
    private val keyProvider: SqlCipherKeyProvider,
    private val keyHolder: DatabaseKeyHolder,
) : ViewModel() {

    private val _state = MutableStateFlow<SettingsResetState>(SettingsResetState.Idle)
    val state: StateFlow<SettingsResetState> = _state.asStateFlow()

    private val _identity = MutableStateFlow<IdentityBundle?>(null)
    val identity: StateFlow<IdentityBundle?> = _identity.asStateFlow()

    private val _appLockEnabled = MutableStateFlow(preferences.appLockEnabled())
    val appLockEnabled: StateFlow<Boolean> = _appLockEnabled.asStateFlow()

    private val _appLockNotice = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val appLockNotice = _appLockNotice.asSharedFlow()

    private val _localDiscoveryEnabled = MutableStateFlow(preferences.localDiscoveryEnabled())
    val localDiscoveryEnabled: StateFlow<Boolean> = _localDiscoveryEnabled.asStateFlow()

    private val _bootstrapPeers = MutableStateFlow(preferences.bootstrapPeers())
    val bootstrapPeers: StateFlow<String> = _bootstrapPeers.asStateFlow()

    private val _nodeAddresses = MutableStateFlow<NodeAddresses?>(null)
    val nodeAddresses: StateFlow<NodeAddresses?> = _nodeAddresses.asStateFlow()

    private val _networkNotice = MutableStateFlow<String?>(null)
    val networkNotice: StateFlow<String?> = _networkNotice.asStateFlow()

    init {
        loadIdentity()
        refreshNodeAddresses()
    }

    /**
     * mDNS toggle. The running node keeps its current behaviour; the
     * new value is read the next time MessageService starts the node.
     */
    fun setLocalDiscoveryEnabled(enabled: Boolean) {
        preferences.setLocalDiscoveryEnabled(enabled)
        _localDiscoveryEnabled.value = enabled
        _networkNotice.value = if (enabled) {
            "Local discovery on. Applies when the P2P service next starts."
        } else {
            "Local discovery off. Peers must be reached through bootstrap addresses."
        }
    }

    fun refreshNodeAddresses() {
        viewModelScope.launch {
            _nodeAddresses.value = NodeAddresses.fromJson(qubeeManager.getNodeAddresses())
        }
    }

    /**
     * Persist the bootstrap list (one multiaddr per line) and dial each
     * entry immediately so the user doesn't have to restart the service
     * to test a manual connection.
     */
    fun saveBootstrapPeers(text: String) {
        val entries = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val normalised = entries.joinToString("\n")
        preferences.setBootstrapPeers(normalised)
        _bootstrapPeers.value = normalised
        viewModelScope.launch {
            var queued = 0
            for (addr in entries) {
                if (qubeeManager.dialPeer(addr)) queued++
            }
            _networkNotice.value = when {
                entries.isEmpty() -> "Bootstrap list cleared."
                queued == entries.size -> "Saved. Dialing $queued address(es)…"
                else -> "Saved. ${entries.size - queued} of ${entries.size} address(es) rejected " +
                    "(node not running or not a valid multiaddr)."
            }
        }
    }

    /**
     * Toggle the screen lock. Enabling also re-wraps the SQLCipher DB
     * key + Rust-core passphrase under an auth-bound Keystore key
     * (binding the local datastore to the unlock); disabling reverts
     * that. Enabling is refused when the device has no biometric AND no
     * device credential — an auth-bound key nobody can satisfy would
     * lock the user out of their own database.
     */
    fun setAppLockEnabled(enabled: Boolean) {
        if (enabled) {
            if (!deviceCanAuthenticate()) {
                _appLockNotice.tryEmit(
                    "Set a screen lock (PIN, pattern, password, or biometric) on your device first.",
                )
                _appLockEnabled.value = false
                return
            }
            val bound = runCatching { keyProvider.enableAuthBinding(keyHolder) }
            if (bound.isFailure) {
                Timber.e(bound.exceptionOrNull(), "Failed to bind DB key to unlock")
                _appLockNotice.tryEmit("Couldn't enable Screen Lock. Try again.")
                _appLockEnabled.value = false
                return
            }
        } else {
            // The pref and the Keystore binding must move together: a
            // pref of "off" with the binding still in place means no
            // unlock prompt ever runs, so the auth-bound key can never
            // be unwrapped and the datastore is locked for good.
            val unbound = runCatching { keyProvider.disableAuthBinding(keyHolder) }
            if (unbound.isFailure) {
                Timber.e(unbound.exceptionOrNull(), "Failed to unbind DB key; leaving binding in place")
                _appLockNotice.tryEmit("Couldn't turn off Screen Lock. Unlock the app and try again.")
                _appLockEnabled.value = true
                return
            }
        }
        preferences.setAppLockEnabled(enabled)
        _appLockEnabled.value = enabled
        appLockManager.onPreferenceChanged()
    }

    private fun deviceCanAuthenticate(): Boolean {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return BiometricManager.from(context).canAuthenticate(authenticators) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /// Pull the active onboarding bundle (display name, fingerprint,
    /// `qubee://identity/<token>` share link) so the Settings UI can
    /// expose it. Best-effort: a missing / unparseable bundle leaves
    /// the Identity panel in an empty state but doesn't break the
    /// rest of Settings.
    private fun loadIdentity() {
        viewModelScope.launch {
            val raw = try {
                qubeeManager.loadOnboardingBundle()
            } catch (e: Exception) {
                Timber.e(e, "loadOnboardingBundle threw")
                null
            }
            _identity.value = IdentityBundle.fromJson(raw)
        }
    }

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
