package com.qubee.messenger.ui.main

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavController
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import androidx.navigation.ui.setupWithNavController
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.qubee.messenger.R
import com.qubee.messenger.databinding.ActivityMainBinding
import com.qubee.messenger.ui.settings.SettingsActivity
import com.qubee.messenger.util.PermissionHelper
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import timber.log.Timber

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var navController: NavController
    private lateinit var appBarConfiguration: AppBarConfiguration
    
    private val viewModel: MainViewModel by viewModels()

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

        setupToolbar()
        setupNavigation()
        setupObservers()
        
        // Check and request permissions
        checkPermissions()
        
        Timber.d("MainActivity created")
    }

    private fun setupToolbar() {
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(true)
    }

    private fun setupNavigation() {
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        navController = navHostFragment.navController

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
                        val action = MainFragmentDirections.actionToChat(event.contactId)
                        navController.navigate(action)
                    }
                    is MainViewModel.NavigationEvent.OpenSettings -> {
                        startActivity(Intent(this@MainActivity, SettingsActivity::class.java))
                    }
                }
            }
        }
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
                navController.navigate(R.id.action_to_contact_selection)
                true
            }
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
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

