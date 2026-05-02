package com.qubee.messenger.data.repository

import javax.inject.Inject
import javax.inject.Singleton

// Pre-alpha placeholder — calling not implemented yet.

@Singleton
class CallRepository @Inject constructor() {

    suspend fun initiateCall(contactId: String, isVideo: Boolean) {}
    suspend fun initiateVerificationCall(contactId: String) {}

    companion object {
        @Volatile private var INSTANCE: CallRepository? = null
        fun getInstance(): CallRepository =
            INSTANCE ?: synchronized(this) { INSTANCE ?: CallRepository().also { INSTANCE = it } }
    }
}
