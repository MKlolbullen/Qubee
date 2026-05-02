package com.qubee.messenger.ui.contacts.verification

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

// Pre-alpha placeholder. The OOB / SAS verification gesture is post-alpha
// (priority 8 in the plan). This Activity exists only so the
// ContactsFragment "Verify" button has a destination — it shows the
// contact id and a "verification coming soon" message instead of
// performing any cryptographic comparison.

class ContactVerificationActivity : ComponentActivity() {

    enum class VerificationMethod { QR_CODE, NFC, SHARED_SECRET }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val identityId = intent.getStringExtra(EXTRA_IDENTITY_ID).orEmpty()
        val method = intent.getStringExtra(EXTRA_METHOD).orEmpty()
        setContent { VerificationStub(identityId, method) }
    }

    companion object {
        private const val EXTRA_IDENTITY_ID = "identityId"
        private const val EXTRA_METHOD = "method"

        fun createIntent(
            context: Context,
            identityId: String,
            method: VerificationMethod,
        ): Intent = Intent(context, ContactVerificationActivity::class.java).apply {
            putExtra(EXTRA_IDENTITY_ID, identityId)
            putExtra(EXTRA_METHOD, method.name)
        }
    }
}

@Composable
private fun VerificationStub(identityId: String, method: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = "Verification coming soon", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
        Text(text = "Method: $method", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(8.dp))
        Text(text = "Identity: $identityId", style = MaterialTheme.typography.bodySmall)
    }
}
