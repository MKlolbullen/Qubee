package com.qubee.messenger.ui.settings

import android.content.Context
import com.qubee.messenger.crypto.QubeeManager
import com.qubee.messenger.data.repository.PreferenceRepository
import com.qubee.messenger.security.AppLockManager
import com.qubee.messenger.security.DatabaseKeyHolder
import com.qubee.messenger.security.SqlCipherKeyProvider
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.doThrow
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify

@OptIn(ExperimentalCoroutinesApi::class)
class SettingsViewModelTest {
    @Test
    fun failed_disable_keeps_setting_and_ui_enabled() = runTest {
        Dispatchers.setMain(UnconfinedTestDispatcher(testScheduler))
        try {
            val preferences = mock(PreferenceRepository::class.java)
            val keys = mock(SqlCipherKeyProvider::class.java)
            val lock = mock(AppLockManager::class.java)
            val holder = DatabaseKeyHolder()
            `when`(preferences.appLockEnabled()).thenReturn(true)
            doThrow(SecurityException("Injected persistence failure"))
                .`when`(keys).disableAuthBinding(holder)
            val viewModel = SettingsViewModel(
                mock(Context::class.java), mock(QubeeManager::class.java),
                preferences, lock, keys, holder,
            )
            val notice = async(start = CoroutineStart.UNDISPATCHED) { viewModel.appLockNotice.first() }
            viewModel.setAppLockEnabled(false)
            assertTrue(notice.await().contains("Couldn't change Screen Lock"))
            assertTrue(viewModel.appLockEnabled.value)
            verify(preferences, never()).setAppLockEnabled(false)
            verify(lock, never()).onPreferenceChanged()
        } finally {
            Dispatchers.resetMain()
        }
    }

    @Test
    fun failed_preference_write_rolls_back_binding_without_publishing_toggle() = runTest {
        Dispatchers.setMain(UnconfinedTestDispatcher(testScheduler))
        try {
            val preferences = mock(PreferenceRepository::class.java)
            val keys = mock(SqlCipherKeyProvider::class.java)
            val lock = mock(AppLockManager::class.java)
            val holder = DatabaseKeyHolder()
            `when`(preferences.appLockEnabled()).thenReturn(true)
            `when`(preferences.setAppLockEnabled(false)).thenReturn(false)
            `when`(preferences.setAppLockEnabled(true)).thenReturn(true)
            val viewModel = SettingsViewModel(
                mock(Context::class.java), mock(QubeeManager::class.java),
                preferences, lock, keys, holder,
            )
            val notice = async(start = CoroutineStart.UNDISPATCHED) { viewModel.appLockNotice.first() }

            viewModel.setAppLockEnabled(false)

            assertTrue(notice.await().contains("Couldn't change Screen Lock"))
            assertTrue(viewModel.appLockEnabled.value)
            verify(keys).disableAuthBinding(holder)
            verify(keys).enableAuthBinding(holder)
            verify(preferences).setAppLockEnabled(true)
            verify(lock, never()).onPreferenceChanged()
        } finally {
            Dispatchers.resetMain()
        }
    }

    @Test
    fun successful_durable_preference_write_publishes_toggle() = runTest {
        Dispatchers.setMain(UnconfinedTestDispatcher(testScheduler))
        try {
            val preferences = mock(PreferenceRepository::class.java)
            val keys = mock(SqlCipherKeyProvider::class.java)
            val lock = mock(AppLockManager::class.java)
            val holder = DatabaseKeyHolder()
            `when`(preferences.appLockEnabled()).thenReturn(true)
            `when`(preferences.setAppLockEnabled(false)).thenReturn(true)
            val viewModel = SettingsViewModel(
                mock(Context::class.java), mock(QubeeManager::class.java),
                preferences, lock, keys, holder,
            )

            viewModel.setAppLockEnabled(false)

            assertTrue(!viewModel.appLockEnabled.value)
            verify(preferences).setAppLockEnabled(false)
            verify(lock).onPreferenceChanged()
        } finally {
            Dispatchers.resetMain()
        }
    }
}
