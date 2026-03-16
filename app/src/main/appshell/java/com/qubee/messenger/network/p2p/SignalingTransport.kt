package com.qubee.messenger.network.p2p

import kotlinx.coroutines.flow.Flow

interface SignalingTransport {
    val transportName: String
    suspend fun start(localHandle: String)
    suspend fun stop()
    suspend fun publish(message: SignalingMessage)
    fun incoming(): Flow<SignalingMessage>
}
