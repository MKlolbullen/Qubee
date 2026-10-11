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

    /** PeerIds with at least one live libp2p connection right now. */
    val connectedPeers: StateFlow<Set<String>> = _connectedPeers.asStateFlow()

    /** Record a new dialable address from `NodeEvent.Listening`, deduped and filtered. */
    fun onListening(multiaddr: String) {
        if (isLocalOnly(multiaddr)) return
        _listenAddresses.update { current -> if (multiaddr in current) current else current + multiaddr }
    }

    /** Drop an address that is no longer bound, from `NodeEvent.ListenAddrExpired`. */
    fun onListenAddrExpired(multiaddr: String) {
        _listenAddresses.update { current -> current - multiaddr }
    }

    /** Add a peer to the connected set on its first established connection. */
    fun onPeerConnected(peerId: String) {
        _connectedPeers.update { current -> current + peerId }
    }

    /** Remove a peer from the connected set once its last connection closes. */
    fun onPeerDisconnected(peerId: String) {
        _connectedPeers.update { current -> current - peerId }
    }

    /** Clear all state; called when the P2P node stops so stale data doesn't linger. */
    fun reset() {
        _listenAddresses.value = emptyList()
        _connectedPeers.value = emptySet()
    }

    /** True for loopback or link-local addresses, which are never useful to another device. */
    private fun isLocalOnly(multiaddr: String): Boolean =
        multiaddr.startsWith("/ip4/127.") ||
            multiaddr.startsWith("/ip6/::1/") ||
            multiaddr.startsWith("/ip4/169.254.") ||
            multiaddr.startsWith("/ip6/fe80")
}
