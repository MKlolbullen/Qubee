package com.qubee.messenger.network.p2p

data class SignalingMessage(
    val type: String,
    val peerHandle: String,
    val payload: String,
    val sentAt: Long,
)
