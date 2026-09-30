package com.qubee.messenger.ui.onboarding

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.NavOptions
import androidx.navigation.fragment.findNavController
import com.qubee.messenger.R
import com.qubee.messenger.service.MessageService
import dagger.hilt.android.AndroidEntryPoint

/**
 * Hosts [OnboardingScreen] inside the navigation graph so MainActivity
 * can route to it before the user has minted an identity.
 *
 * On completion we navigate to the conversations tab AND pop ourselves
 * off the back stack with `setPopUpTo(R.id.onboardingFragment, true)`,
 * so the system back button after onboarding exits the app instead of
 * sending the user back to the "Welcome" screen.
 */
@AndroidEntryPoint
class OnboardingFragment : Fragment() {

    private val viewModel: OnboardingViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent {
            OnboardingScreen(viewModel = viewModel) {
                // The service (and its node) started before the identity
                // existed; have it take the identity's subscriptions and
                // announce the prekey bundle now instead of at next launch.
                MessageService.identityReady(requireContext())
                val nav = findNavController()
                nav.navigate(
                    R.id.navigation_conversations,
                    null,
                    NavOptions.Builder()
                        .setPopUpTo(R.id.onboardingFragment, /* inclusive = */ true)
                        .build(),
                )
            }
        }
    }
}
