package com.qubee.messenger.ui.main

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import android.view.WindowManager
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.Lifecycle
import com.qubee.messenger.security.AppLockManager
import com.qubee.messenger.security.BiometricAuthenticator
import com.qubee.messenger.ui.lock.UnlockScreen
import androidx.navigation.NavController
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.qubee.messenger.R
import com.qubee.messenger.data.repository.PreferenceRepository
import com.qubee.messenger.databinding.ActivityMainBinding
import com.qubee.messenger.service.MessageService
import com.qubee.messenger.util.PermissionHelper
import javax.inject.Inject
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import timber.log.Timber

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var navController: NavController
    private lateinit var appBarConfiguration: AppBarConfiguration
    
    private val viewModel: MainViewModel by viewModels()

    @Inject
    lateinit var preferences: PreferenceRepository

    @Inject
    lateinit var appLockManager: AppLockManager

    private val biometricAuthenticator by lazy { BiometricAuthenticator(this) }

    // Full-screen Compose overlay that covers the fragment host while
    // the app is locked. Added on top of the activity's content view so
    // no conversation UI is ever visible behind the gate.
    private lateinit var lockOverlay: ComposeView
    private var lockError by mutableStateOf<String?>(null)
    private var promptInFlight = false

    // Permission launcher
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        handlePermissionResults(permissions)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupLockOverlay()

        setupToolbar()
        setupNavigation(isFreshLaunch = savedInstanceState == null)
        setupObservers()
        
        // Check and request permissions
        checkPermissions()

        // Start the P2P background service
        MessageService.start(this)

        Timber.d("MainActivity created & Service started")
    }

    /**
     * `launchMode="singleTask"` means subsequent `qubee://...` deep
     * links arrive here instead of restarting the activity. Hand them
     * back to the NavController so the `<deepLink>` entries in
     * `nav_graph.xml` (the single source of truth for deep-link
     * routing) take effect.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (::navController.isInitialized) {
            navController.handleDeepLink(intent)
        }
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(true)
    }

    private fun setupNavigation(isFreshLaunch: Boolean) {
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        navController = navHostFragment.navController

        // The layout no longer carries `app:navGraph`, so we always
        // inflate here. Only the *start destination* is conditional on
        // a fresh launch — on rotation/process-death-restore, the
        // controller restores its previous back stack from saved state
        // when the graph is reassigned.
        val graph = navController.navInflater.inflate(R.navigation.nav_graph)
        if (isFreshLaunch) {
            graph.setStartDestination(
                if (preferences.isOnboarded()) R.id.navigation_conversations
                else R.id.onboardingFragment
            )
        }
        navController.graph = graph

        // Setup bottom navigation
        binding.bottomNavigation.setupWithNavController(navController)

        // Setup app bar configuration
        appBarConfiguration = AppBarConfiguration(
            setOf(
                R.id.navigation_conversations,
                R.id.navigation_contacts,
                R.id.navigation_settings
            )
        )
        setupActionBarWithNavController(navController, appBarConfiguration)

        // Handle navigation changes
        navController.addOnDestinationChangedListener { _, destination, _ ->
            // Onboarding gets the full screen — no toolbar, no bottom
            // nav, since the user hasn't picked an identity yet and
            // there's nowhere meaningful to navigate to.
            val isOnboarding = destination.id == R.id.onboardingFragment
            binding.appBarLayout.visibility =
                if (isOnboarding) View.GONE else View.VISIBLE
            binding.bottomNavigation.visibility =
                if (isOnboarding) View.GONE else View.VISIBLE

            when (destination.id) {
                R.id.navigation_conversations -> {
                    supportActionBar?.title = getString(R.string.title_conversations)
                }
                R.id.navigation_contacts -> {
                    supportActionBar?.title = getString(R.string.title_contacts)
                }
                R.id.navigation_settings -> {
                    supportActionBar?.title = getString(R.string.title_settings)
                }
            }
        }
    }

    private fun setupObservers() {
        lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                when {
                    state.isLoading -> {
                        // Show loading indicator if needed
                    }
                    state.error != null -> {
                        showError(state.error)
                    }
                    state.isInitialized -> {
                        // App is ready
                        Timber.d("App initialized successfully")
                    }
                }
            }
        }

        lifecycleScope.launch {
            viewModel.navigationEvents.collect { event ->
                when (event) {
                    is MainViewModel.NavigationEvent.OpenChat -> {
                        // Navigate to chat
                        // Note: Ensure your nav_graph.xml has an action or global action to chatFragment
                        // using SafeArgs e.g.: MainFragmentDirections.actionToChat(event.contactId)
                        // For now we use the ID defined in nav_graph.xml
                        val bundle = Bundle().apply { putString("contactId", event.contactId) }
                        navController.navigate(R.id.chatFragment, bundle)
                    }
                    is MainViewModel.NavigationEvent.OpenSettings -> {
                        // Navigate to the real Settings fragment (bottom-nav
                        // destination). The old placeholder SettingsActivity
                        // is gone.
                        navController.navigate(R.id.navigation_settings)
                    }
                    is MainViewModel.NavigationEvent.OpenContactSelection -> {
                        navController.navigate(R.id.contactSelectionFragment)
                    }
                }
            }
        }
    }

    /**
     * Add the lock gate as the top-most view in the activity window and
     * bind it to [AppLockManager.locked]. While locked we also set
     * `FLAG_SECURE` so the gate (not the conversations behind it) is
     * what shows in the recents thumbnail.
     */
    private fun setupLockOverlay() {
        lockOverlay = ComposeView(this).apply {
            setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
            setContent {
                UnlockScreen(
                    error = lockError,
                    onUnlockClick = { showUnlockPrompt() },
                )
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                appLockManager.locked.collect { locked ->
                    if (locked) showLockOverlay() else hideLockOverlay()
                }
            }
        }
    }

    /**
     * Attach the gate on top of the activity content (only while
     * locked — we add/remove rather than toggle visibility so no
     * dormant full-screen view lingers hidden in the hierarchy) and
     * set `FLAG_SECURE` so the gate, not the conversations, is what
     * the recents thumbnail captures.
     */
    private fun showLockOverlay() {
        if (lockOverlay.parent == null) {
            addContentView(
                lockOverlay,
                FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT,
                ),
            )
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        showUnlockPrompt()
    }

    private fun hideLockOverlay() {
        (lockOverlay.parent as? android.view.ViewGroup)?.removeView(lockOverlay)
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        lockError = null
    }

    /**
     * Launch the biometric / device-credential prompt. Guards against
     * re-entrancy (the state collector and the on-screen button can
     * both call this). If the device has no biometric AND no device
     * credential set up, there is nothing to authenticate against —
     * fail open rather than trap the user out of their own app.
     */
    private fun showUnlockPrompt() {
        if (promptInFlight) return
        if (!biometricAuthenticator.canAuthenticate()) {
            Timber.w("No biometric or device credential enrolled — unlocking without a gate")
            appLockManager.unlock()
            return
        }
        promptInFlight = true
        biometricAuthenticator.authenticate(
            title = getString(R.string.app_lock_prompt_title),
            subtitle = getString(R.string.app_lock_prompt_subtitle),
            onSuccess = {
                promptInFlight = false
                appLockManager.unlock()
            },
            onFail = { reason ->
                promptInFlight = false
                lockError = reason
            },
        )
    }

    override fun onStart() {
        super.onStart()
        appLockManager.onEnterForeground()
    }

    override fun onStop() {
        super.onStop()
        appLockManager.onEnterBackground()
    }

    private fun checkPermissions() {
        val requiredPermissions = PermissionHelper.getRequiredPermissions()
        val missingPermissions = requiredPermissions.filter { permission ->
            ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            if (shouldShowPermissionRationale(missingPermissions)) {
                showPermissionRationale(missingPermissions)
            } else {
                requestPermissions(missingPermissions)
            }
        } else {
            viewModel.onPermissionsGranted()
        }
    }

    private fun shouldShowPermissionRationale(permissions: List<String>): Boolean {
        return permissions.any { shouldShowRequestPermissionRationale(it) }
    }

    private fun showPermissionRationale(permissions: List<String>) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.permissions_required_title)
            .setMessage(R.string.permissions_required_message)
            .setPositiveButton(R.string.grant_permissions) { _, _ ->
                requestPermissions(permissions)
            }
            .setNegativeButton(R.string.cancel) { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }

    private fun requestPermissions(permissions: List<String>) {
        permissionLauncher.launch(permissions.toTypedArray())
    }

    private fun handlePermissionResults(permissions: Map<String, Boolean>) {
        val deniedPermissions = permissions.filterValues { !it }.keys
        
        if (deniedPermissions.isEmpty()) {
            viewModel.onPermissionsGranted()
        } else {
            val criticalPermissions = deniedPermissions.filter { permission ->
                PermissionHelper.isCriticalPermission(permission)
            }
            
            if (criticalPermissions.isNotEmpty()) {
                showCriticalPermissionsDenied(criticalPermissions)
            } else {
                viewModel.onPermissionsGranted()
            }
        }
    }

    private fun showCriticalPermissionsDenied(permissions: List<String>) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.critical_permissions_denied_title)
            .setMessage(R.string.critical_permissions_denied_message)
            .setPositiveButton(R.string.app_settings) { _, _ ->
                PermissionHelper.openAppSettings(this)
            }
            .setNegativeButton(R.string.exit_app) { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }

    private fun showError(error: String) {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.error_title)
            .setMessage(error)
            .setPositiveButton(R.string.ok, null)
            .show()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_search -> {
                // Handle search
                true
            }
            R.id.action_new_chat -> {
                // Navigate to contact selection
                navController.navigate(R.id.contactSelectionFragment)
                true
            }
            R.id.action_new_group -> {
                // Top-level entry to the create-or-scan group flow.
                // groupInviteFragment hosts both halves: minting a new
                // group (with a fresh invite QR) and accepting one.
                navController.navigate(R.id.groupInviteFragment)
                true
            }
            R.id.action_settings -> {
                navController.navigate(R.id.navigation_settings)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        return navController.navigateUp(appBarConfiguration) || super.onSupportNavigateUp()
    }

    override fun onDestroy() {
        super.onDestroy()
        Timber.d("MainActivity destroyed")
    }
}
