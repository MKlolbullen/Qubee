package com.qubee.messenger.security

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat

/**
 * Thin wrapper over [BiometricPrompt] that authenticates with a strong
 * biometric (fingerprint / face) OR the device credential (PIN,
 * pattern, password) in a single prompt.
 *
 * The combined `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` authenticator
 * is only valid via `setAllowedAuthenticators` on API 30+. On API
 * 24–29 the same behaviour comes from the (now-deprecated)
 * `setDeviceCredentialAllowed(true)`, which this class selects
 * automatically so a PIN fallback works everywhere down to minSdk 24.
 */
class BiometricAuthenticator(private val activity: AppCompatActivity) {

    /** Whether the device can satisfy a biometric-or-credential prompt. */
    fun canAuthenticate(): Boolean {
        val manager = BiometricManager.from(activity)
        if (manager.canAuthenticate(allowedAuthenticators()) == BiometricManager.BIOMETRIC_SUCCESS) {
            return true
        }
        // Pre-30 can't query DEVICE_CREDENTIAL through BiometricManager,
        // and BIOMETRIC_STRONG alone reports non-success on a
        // credential-only device (PIN/pattern/password, no biometric).
        // Those devices CAN still authenticate via the credential
        // prompt (setDeviceCredentialAllowed), so treat a secure
        // keyguard as authenticatable — otherwise the caller would
        // fail open and the lock would silently do nothing for them.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            return keyguard.isDeviceSecure
        }
        return false
    }

    /**
     * Show the prompt. [onSuccess] fires on a verified unlock;
     * [onFail] fires on an unrecoverable error (hardware unavailable,
     * user cancelled, too many attempts) with a human-readable reason
     * — the caller keeps the lock in place. Transient per-attempt
     * failures (one wrong fingerprint) are handled inside the prompt
     * and do not call back.
     */
    fun authenticate(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onFail: (reason: String) -> Unit,
    ) = authenticate(title, subtitle, cryptoObject = null, onSuccess = { onSuccess() }, onFail = onFail)

    /**
     * Prompt variant that carries a [BiometricPrompt.CryptoObject] — the
     * database-binding unlock passes the auth-bound decrypt cipher so
     * the ceremony itself authorises the key use. [onSuccess] receives
     * the authorised result (its `cryptoObject.cipher` can then unwrap
     * the DB key).
     *
     * Platform note: a `CryptoObject` prompt supports the device
     * credential (PIN/pattern/password) fallback only on API 30+. On
     * API 24–29 a crypto-bound prompt is biometric-only — the auth-bound
     * key there uses a per-use validity that the framework satisfies via
     * biometric. Callers that need the PIN fallback on old devices fall
     * back to the non-crypto prompt.
     */
    fun authenticate(
        title: String,
        subtitle: String,
        cryptoObject: BiometricPrompt.CryptoObject?,
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onFail: (reason: String) -> Unit,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess(result)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFail(errString.toString())
                }
            },
        )

        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)

        // A CryptoObject prompt can only offer the device credential on
        // API 30+; below that it must be biometric-only, and a negative
        // button is required.
        val credentialAllowed = cryptoObject == null || Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
        if (credentialAllowed && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(allowedAuthenticators())
        } else if (credentialAllowed) {
            @Suppress("DEPRECATION")
            builder.setDeviceCredentialAllowed(true)
        } else {
            builder.setAllowedAuthenticators(BIOMETRIC_STRONG)
            builder.setNegativeButtonText(activity.getString(android.R.string.cancel))
        }

        if (cryptoObject != null) {
            prompt.authenticate(builder.build(), cryptoObject)
        } else {
            prompt.authenticate(builder.build())
        }
    }

    private fun allowedAuthenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        } else {
            // canAuthenticate() on older APIs is happier querying the
            // biometric class alone; the credential fallback is still
            // offered at prompt time via setDeviceCredentialAllowed.
            BIOMETRIC_STRONG
        }
}
