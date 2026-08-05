package com.qubee.messenger.security

import android.os.SystemClock
import com.qubee.messenger.data.repository.PreferenceRepository
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * App-level screen-lock state and auto-lock policy.
 *
 * When [PreferenceRepository.appLockEnabled] is on, the app presents a
 * biometric / device-credential gate on cold start and whenever it
 * returns to the foreground after being backgrounded for longer than
 * [GRACE_MILLIS]. The grace window keeps a momentary app-switch (e.g.
 * tapping a shared link, granting a permission) from forcing a
 * re-auth, while a genuine "put the phone down" locks.
 *
 * Scope: this gates the **UI only**. The SQLCipher key is still
 * unwrapped without user auth (`setUserAuthenticationRequired(false)`
 * — see SECURITY.md); binding the database key to the lock is the
 * deeper, separately-tracked change. Treat this as defense against a
 * casual "someone picked up my unlocked phone", not against a
 * forensic attacker with the device.
 *
 * State is process-scoped (a `@Singleton`), deliberately NOT persisted:
 * a fresh process always starts [locked] when the feature is on, and
 * the background timestamp uses [SystemClock.elapsedRealtime] so a
 * wall-clock change can't shrink the grace window.
 */
@Singleton
class AppLockManager @Inject constructor(
    private val preferences: PreferenceRepository,
) {
    private val _locked = MutableStateFlow(preferences.appLockEnabled())

    /** True while the unlock gate should be shown over the app UI. */
    val locked: StateFlow<Boolean> = _locked.asStateFlow()

    /** Elapsed-realtime stamp of when the app last went to background,
     *  or `null` while foregrounded / never-backgrounded. */
    private var backgroundedAtMillis: Long? = null

    /** Whether the lock feature is currently switched on. */
    fun isEnabled(): Boolean = preferences.appLockEnabled()

    /**
     * Called when the app's last activity stops. Records the time so
     * [onEnterForeground] can decide whether the grace window elapsed.
     */
    fun onEnterBackground() {
        backgroundedAtMillis = SystemClock.elapsedRealtime()
    }

    /**
     * Called when the app returns to the foreground. Locks if the
     * feature is on and we've been backgrounded past the grace window
     * (or the background time is unknown — fail closed).
     */
    fun onEnterForeground() {
        if (!isEnabled()) {
            _locked.value = false
            return
        }
        val since = backgroundedAtMillis
        val elapsed = if (since == null) Long.MAX_VALUE else SystemClock.elapsedRealtime() - since
        if (elapsed >= GRACE_MILLIS) {
            _locked.value = true
        }
        backgroundedAtMillis = null
    }

    /** Mark the app unlocked after a successful auth. */
    fun unlock() {
        _locked.value = false
        backgroundedAtMillis = null
    }

    /**
     * Re-evaluate against the current preference — called when the user
     * flips the toggle in Settings. Turning the feature OFF clears any
     * active lock; turning it ON does not retroactively lock the
     * already-open session (the user is right there having just set it).
     */
    fun onPreferenceChanged() {
        if (!isEnabled()) _locked.value = false
    }

    companion object {
        /** Backgrounded for less than this → no re-lock on return. */
        const val GRACE_MILLIS: Long = 15_000L
    }
}
