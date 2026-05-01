package com.qubee.messenger.data.repository

import com.qubee.messenger.ui.contacts.ContactVerificationResult
import javax.inject.Inject
import javax.inject.Singleton

// Pre-alpha placeholder — OOB / SAS verification gesture not yet
// implemented (post-alpha priority 8 in the plan).

@Singleton
class VerificationRepository @Inject constructor() {

    suspend fun verifyWithQRCode(qrData: String): ContactVerificationResult =
        ContactVerificationResult(success = false, contactName = "", verificationMethod = "QR_CODE", error = "not implemented")

    suspend fun verifyWithNFC(nfcData: ByteArray): ContactVerificationResult =
        ContactVerificationResult(success = false, contactName = "", verificationMethod = "NFC", error = "not implemented")

    companion object {
        @Volatile private var INSTANCE: VerificationRepository? = null
        fun getInstance(): VerificationRepository =
            INSTANCE ?: synchronized(this) { INSTANCE ?: VerificationRepository().also { INSTANCE = it } }
    }
}
