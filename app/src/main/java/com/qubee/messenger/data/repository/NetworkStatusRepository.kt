package com.qubee.messenger.data.repository

import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Live view of the P2P node for the UI: the addresses this device can
 * be reached at and the peers it is connected to. MessageService feeds
 * it from the native callbacks and resets it when the node restarts.
 */
@Singleton
class NetworkStatusRepository @Inject constructor() {

    private val _listenAddresses = MutableStateFlow<List<String>>(emptyList())

    /**
     * Dialable addresses with the `/p2p/<PeerId>` suffix. Loopback and
     * link-local entries are dropped: nothing outside this device can
     * use them, and they would bury the one address that matters.
     */
    val listenAddresses: StateFlow<List<String>> = _listenAddresses.asStateFlow()

    private val _connectedPeers = MutableStateFlow<Set<String>>(emptySet())
    val connectedPeers: StateFlow<Set<String>> = _connectedPeers.asStateFlow()

    fun onListening(multiaddr: String) {
        if (isLocalOnly(multiaddr)) return
        _listenAddresses.update { current -> if (multiaddr in current) current else current + multiaddr }
    }

    fun onListenAddrExpired(multiaddr: String) {
        _listenAddresses.update { current -> current - multiaddr }
    }

    fun onPeerConnected(peerId: String) {
        _connectedPeers.update { current -> current + peerId }
    }

    fun onPeerDisconnected(peerId: String) {
        _connectedPeers.update { current -> current - peerId }
    }

    fun reset() {
        _listenAddresses.value = emptyList()
        _connectedPeers.value = emptySet()
    }

    private fun isLocalOnly(multiaddr: String): Boolean =
        multiaddr.startsWith("/ip4/127.") ||
            multiaddr.startsWith("/ip6/::1/") ||
            multiaddr.startsWith("/ip4/169.254.") ||
            multiaddr.startsWith("/ip6/fe80")
}
