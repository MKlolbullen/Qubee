package com.qubee.messenger.network.p2p

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

class ChannelRehydrationManager(
    private val onRehydrate: suspend (peerHandle: String, iceRestart: Boolean) -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val failureCounts = ConcurrentHashMap<String, Int>()

    fun reportHealthy(peerHandle: String) {
        failureCounts.remove(peerHandle)
    }

    fun schedule(peerHandle: String) {
        val failures = failureCounts.merge(peerHandle, 1) { a, _ -> a + 1 } ?: 1
        val backoffMs = when (failures) {
            1 -> 1500L
            2 -> 4000L
            3 -> 8000L
            else -> 15000L
        }
        scope.launch {
            delay(backoffMs)
            onRehydrate(peerHandle, true)
        }
    }
}
