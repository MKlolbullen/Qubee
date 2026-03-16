package com.qubee.messenger.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.qubee.messenger.ui.theme.QubeeTheme

class MainActivity : ComponentActivity() {
    private val viewModel by viewModels<AppViewModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        enableEdgeToEdge()
        setContent {
            QubeeTheme {
                QubeeApp(
                    viewModel = viewModel,
                    onRequestUnlock = ::requestVaultUnlock,
                )
            }
        }
    }

    private fun requestVaultUnlock() {
        val biometricManager = BiometricManager.from(this)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val canAuthenticate = biometricManager.canAuthenticate(authenticators)
        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) {
            viewModel.onUnlockCancelledOrFailed("Device authentication unavailable (code $canAuthenticate).")
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                viewModel.onUnlockAuthenticated()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                viewModel.onUnlockCancelledOrFailed(errString.toString())
            }

            override fun onAuthenticationFailed() {
                viewModel.onUnlockCancelledOrFailed("Authentication failed. The vault remains closed.")
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Qubee")
            .setSubtitle("Open the keystore-backed SQLCipher vault")
            .setAllowedAuthenticators(authenticators)
            .build()

        prompt.authenticate(promptInfo)
    }
}
