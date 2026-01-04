// app/src/main/java/com/qubee/messenger/network/NetworkCallback.kt

package com.qubee.messenger.network

/**
 * Interface for receiving events from the native Rust P2P node.
 */
interface NetworkCallback {
    /**
     * Called when a P2P message is received from the swarm.
     * @param senderId The Peer ID (string) of the sender.
     * @param data The raw byte content (likely encrypted).
     */
    fun onMessageReceived(senderId: String, data: ByteArray)

    /**
     * Called when a new peer is discovered in the swarm (mDNS/DHT).
     * @param peerId The Peer ID of the discovered node.
     */
    fun onPeerDiscovered(peerId: String)
}
