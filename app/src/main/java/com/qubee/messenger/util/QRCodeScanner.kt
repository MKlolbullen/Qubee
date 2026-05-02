package com.qubee.messenger.util

import androidx.fragment.app.Fragment

// Pre-alpha placeholder. The real QR scan path runs through ML Kit /
// CameraX in AddContactFragment + GroupInviteFragment; this class
// exists only so the half-built ContactsFragment compiles. No camera
// is actually started.

class QRCodeScanner(
    @Suppress("UNUSED_PARAMETER") fragment: Fragment,
    @Suppress("UNUSED_PARAMETER") onResult: (String) -> Unit,
) {
    fun startScanning() = Unit
}
