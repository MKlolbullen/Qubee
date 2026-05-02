package com.qubee.messenger.util

import android.app.Activity

// Pre-alpha placeholder. NFC verification is intentionally not in the
// alpha scope — see plan note "No NFC verification path". The class
// exists only so the half-built ContactsFragment compiles.

class NFCManager(
    @Suppress("UNUSED_PARAMETER") activity: Activity,
    @Suppress("UNUSED_PARAMETER") onResult: (ByteArray) -> Unit,
) {
    fun isNFCAvailable(): Boolean = false
    fun enableNFCReading() = Unit
    fun disableNFCReading() = Unit
}
