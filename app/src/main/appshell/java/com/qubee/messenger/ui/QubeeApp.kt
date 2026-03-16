package com.qubee.messenger.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.PersonAddAlt1
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.qubee.messenger.model.VaultLockState
import com.qubee.messenger.ui.screens.ChatScreen
import com.qubee.messenger.ui.screens.ConnectivityScreen
import com.qubee.messenger.ui.screens.ConversationsScreen
import com.qubee.messenger.ui.screens.DangerZoneScreen
import com.qubee.messenger.ui.screens.InviteScreen
import com.qubee.messenger.ui.screens.LinkedDevicesScreen
import com.qubee.messenger.ui.screens.OnboardingScreen
import com.qubee.messenger.ui.screens.SettingsScreen
import com.qubee.messenger.ui.screens.TrustDetailsScreen
import com.qubee.messenger.ui.screens.UnlockScreen

private object Routes {
    const val Onboarding = "onboarding"
    const val Conversations = "conversations"
    const val Invite = "invite"
    const val Settings = "settings"
    const val LinkedDevices = "linked-devices"
    const val Connectivity = "connectivity"
    const val DangerZone = "danger-zone"
    const val Chat = "chat/{conversationId}"
    const val Trust = "trust/{conversationId}"
    fun chat(conversationId: String) = "chat/$conversationId"
    fun trust(conversationId: String) = "trust/$conversationId"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QubeeApp(
    viewModel: AppViewModel = viewModel(),
    onRequestUnlock: () -> Unit,
) {
    val navController = rememberNavController()
    val uiState = viewModel.uiState
    val backStackEntry by navController.currentBackStackEntryAsState()
    val route = backStackEntry?.destination?.route ?: Routes.Onboarding

    if (uiState.vaultStatus.state != VaultLockState.Unlocked) {
        Surface(modifier = androidx.compose.ui.Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            UnlockScreen(
                vaultStatus = uiState.vaultStatus,
                nativeStatus = uiState.nativeStatus,
                relayStatus = uiState.relayStatus,
                onUnlock = {
                    viewModel.beginUnlock()
                    onRequestUnlock()
                },
            )
        }
        return
    }

    LaunchedEffect(uiState.onboardingComplete) {
        if (uiState.onboardingComplete) {
            navController.navigate(Routes.Conversations) {
                popUpTo(Routes.Onboarding) { inclusive = true }
                launchSingleTop = true
            }
        }
    }

    LaunchedEffect(uiState.lastImportedConversationId) {
        val conversationId = uiState.lastImportedConversationId ?: return@LaunchedEffect
        viewModel.openConversation(conversationId)
        navController.navigate(Routes.chat(conversationId))
        viewModel.consumeImportedConversationNavigation()
    }

    val title = when {
        route.startsWith("trust/") -> "Trust details"
        route.startsWith("chat/") -> uiState.activeConversation?.title ?: "Chat"
        route == Routes.Settings -> "Settings"
        route == Routes.Invite -> "Invite"
        route == Routes.LinkedDevices -> "Linked devices"
        route == Routes.Connectivity -> "Connectivity"
        route == Routes.DangerZone -> "Danger zone"
        route == Routes.Conversations -> "Qubee"
        else -> "Welcome"
    }

    Scaffold(
        modifier = androidx.compose.ui.Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        QubeeBrandGlyph(size = 34.dp)
                        Text(
                            text = if (route == Routes.Conversations) "QUBEE" else title,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                },
                navigationIcon = {
                    if (route != Routes.Conversations && route != Routes.Onboarding) {
                        IconButton(onClick = { navController.popBackStack() }) {
                            Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                actions = {
                    if (route == Routes.Conversations) {
                        IconButton(onClick = { navController.navigate(Routes.Invite) }) {
                            Icon(Icons.Rounded.PersonAddAlt1, contentDescription = "Invite")
                        }
                        IconButton(onClick = { navController.navigate(Routes.Settings) }) {
                            Icon(Icons.Rounded.Settings, contentDescription = "Settings")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Surface(modifier = androidx.compose.ui.Modifier.fillMaxSize().padding(padding), color = MaterialTheme.colorScheme.background) {
            NavHost(navController = navController, startDestination = if (uiState.onboardingComplete) Routes.Conversations else Routes.Onboarding) {
                composable(Routes.Onboarding) {
                    OnboardingScreen(nativeStatus = uiState.nativeStatus, relayStatus = uiState.relayStatus, onCreateIdentity = viewModel::completeOnboarding)
                }
                composable(Routes.Conversations) {
                    ConversationsScreen(
                        profile = uiState.profile,
                        nativeStatus = uiState.nativeStatus,
                        relayStatus = uiState.relayStatus,
                        conversations = uiState.conversations,
                        onConversationClick = { conversationId ->
                            viewModel.openConversation(conversationId)
                            navController.navigate(Routes.chat(conversationId))
                        },
                    )
                }
                composable(Routes.Invite) {
                    InviteScreen(
                        inviteShare = uiState.inviteShare,
                        notice = uiState.inviteNotice,
                        onImportInvite = viewModel::importInvite,
                        onInviteShared = viewModel::notifyInviteShared,
                        onDismissNotice = viewModel::dismissNotice,
                    )
                }
                composable(route = Routes.Chat, arguments = listOf(navArgument("conversationId") { type = NavType.StringType })) { entry ->
                    val conversationId = entry.arguments?.getString("conversationId") ?: return@composable
                    if (uiState.activeConversation?.id != conversationId) viewModel.openConversation(conversationId)
                    ChatScreen(
                        conversation = uiState.activeConversation,
                        messages = uiState.messages,
                        relayStatus = uiState.relayStatus,
                        safetyCode = uiState.activeSafetyCode,
                        onVerifyContact = viewModel::verifyActiveConversation,
                        onOpenTrustDetails = { navController.navigate(Routes.trust(conversationId)) },
                        onSend = viewModel::sendMessage,
                    )
                }
                composable(route = Routes.Trust, arguments = listOf(navArgument("conversationId") { type = NavType.StringType })) { entry ->
                    val conversationId = entry.arguments?.getString("conversationId") ?: return@composable
                    if (uiState.activeConversation?.id != conversationId) viewModel.openConversation(conversationId)
                    TrustDetailsScreen(
                        trustDetails = uiState.activeTrustDetails,
                        onVerifyContact = viewModel::verifyActiveConversation,
                        onResetTrust = viewModel::resetActiveConversationTrust,
                    )
                }
                composable(Routes.Settings) {
                    SettingsScreen(
                        profile = uiState.profile,
                        inviteShare = uiState.inviteShare,
                        nativeStatus = uiState.nativeStatus,
                        relayStatus = uiState.relayStatus,
                        onOpenLinkedDevices = { navController.navigate(Routes.LinkedDevices) },
                        onOpenConnectivity = { navController.navigate(Routes.Connectivity) },
                        onOpenDangerZone = { navController.navigate(Routes.DangerZone) },
                    )
                }
                composable(Routes.LinkedDevices) {
                    LinkedDevicesScreen(profile = uiState.profile, linkedDevices = uiState.linkedDevices)
                }
                composable(Routes.Connectivity) {
                    ConnectivityScreen(nativeStatus = uiState.nativeStatus, relayStatus = uiState.relayStatus, diagnostics = uiState.connectivityDiagnostics)
                }
                composable(Routes.DangerZone) {
                    DangerZoneScreen(onConfirmNuke = viewModel::nukeDevice)
                }
            }
        }
    }
}
