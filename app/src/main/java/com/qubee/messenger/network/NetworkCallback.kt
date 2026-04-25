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

    /**
     * Called when an encrypted group message has been received,
     * verified (sender is an active member, signature passes), and
     * AEAD-decrypted with the current group key. Default impl is a
     * no-op so existing callers don't have to opt in immediately.
     *
     * @param groupIdHex hex-encoded GroupId (32 bytes → 64 chars).
     * @param senderIdHex hex-encoded sender IdentityId.
     * @param plaintext the decrypted message body.
     * @param timestampSeconds sender's send time as Unix seconds.
     */
    fun onGroupMessageReceived(
        groupIdHex: String,
        senderIdHex: String,
        plaintext: ByteArray,
        timestampSeconds: Long,
    ) {
        // default no-op
    }
}
