package com.qubee.messenger.ui.groups

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import dagger.hilt.android.AndroidEntryPoint

/**
 * Hosts [GroupInviteScreen] inside the existing fragment-based nav graph
 * so deep links (`qubee://invite/...`) and bottom-bar navigation can
 * land users on it without having to migrate the whole app to Navigation
 * Compose.
 */
@AndroidEntryPoint
class GroupInviteFragment : Fragment() {

    private val viewModel: GroupInviteViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // If the OS handed us a deep link, let the VM decode it eagerly.
        arguments?.getString(ARG_INVITE_LINK)?.takeIf { it.startsWith("qubee://invite/") }
            ?.let { viewModel.decodeScannedLink(it) }

        return ComposeView(requireContext()).apply {
            setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
            setContent {
                GroupInviteScreen(
                    viewModel = viewModel,
                    onAcceptInvite = { /* hooked up once GroupManager is JNI-exposed */ },
                )
            }
        }
    }

    companion object {
        const val ARG_INVITE_LINK = "inviteLink"
    }
}
