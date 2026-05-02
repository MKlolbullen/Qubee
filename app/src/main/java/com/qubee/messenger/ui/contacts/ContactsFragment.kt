package com.qubee.messenger.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.ViewCompositionStrategy
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment

// Pre-alpha placeholder. The full contacts list (search, filter,
// trust-level chips, NFC/QR verification handoff) was scaffolded
// before the underlying storage and verification flows existed.
// Replaced with a "coming soon" stub so the Contacts tab in
// nav_graph.xml has a working destination — see plan A4 + the post-
// alpha priority 8 (OOB / SAS verification gesture) for the real
// implementation. The data class below is referenced by
// VerificationRepository and is kept in this file so its package
// stays stable when the real fragment lands.

class ContactsFragment : Fragment() {

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = ComposeView(requireContext()).apply {
        setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnViewTreeLifecycleDestroyed)
        setContent { ContactsPlaceholder() }
    }
}

@Composable
private fun ContactsPlaceholder() {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = "Contacts", style = MaterialTheme.typography.headlineSmall)
        Text(text = "Coming soon", style = MaterialTheme.typography.bodyMedium)
    }
}

data class ContactVerificationResult(
    val success: Boolean,
    val contactName: String,
    val verificationMethod: String,
    val error: String? = null,
)
