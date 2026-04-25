package com.qubee.messenger.ui.groups

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.NavController
import com.qubee.messenger.util.QrUtils
import dagger.hilt.android.AndroidEntryPoint

/**
 * Hosts [GroupInviteScreen] inside the existing fragment-based nav graph
 * so the `<deepLink>` entry in nav_graph.xml can route directly here
 * when the OS opens a `qubee://invite/...` URI.
 */
@AndroidEntryPoint
class GroupInviteFragment : Fragment() {

    private val viewModel: GroupInviteViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        // Navigation populates KEY_DEEP_LINK_INTENT with the original
        // ACTION_VIEW intent when a deep link launches this destination.
        // Pull the full URI from there so we don't have to reconstruct it
        // from individual path placeholders.
        deepLinkUri()?.takeIf(QrUtils::isInviteLink)?.let(viewModel::decodeScannedLink)

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

    private fun deepLinkUri(): String? {
        val intent: Intent? = arguments?.getParcelable(NavController.KEY_DEEP_LINK_INTENT)
        return intent?.data?.toString()
    }
}
