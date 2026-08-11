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

    /**
     * Fired by the Rust core after a successful handshake event
     * (RequestJoin, KeyRotationAnnounce, KeyDelivery, MemberAdded, RoleChange,
     * RequestStateSync, StateSyncResponse) when the (libp2p PeerId,
     * Qubee IdentityId) pair becomes known. Lets the Android side
     * stamp `Contact.peerId` *before* any encrypted message round-
     * trip — closes the chicken-and-egg gap where the
     * receive-path TOFU population only fires after at least one
     * inbound has arrived.
     *
     * @param peerId       libp2p PeerId of the peer who delivered
     *                     the handshake frame.
     * @param identityIdHex Qubee IdentityId of that peer, hex-encoded
     *                     (64 chars / 32 bytes).
     */
    fun onPeerLinked(peerId: String, identityIdHex: String) {
        // default no-op
    }

    /**
     * Fired by the Rust core when a `MessageAck` arrives for a
     * group message we sent. The acker has already been verified
     * as an active member of the group and their signature
     * checked — this side just looks up the local Message row by
     * `messageIdHex` and bumps its delivered-ack list.
     *
     * Self-acks (we ack'd our own message) are filtered Rust-side
     * and never reach here.
     *
     * @param groupIdHex     hex-encoded GroupId.
     * @param messageIdHex   32-char hex of the canonical group-
     *                       message id; matches `Message.wireId`.
     * @param ackerIdHex     hex-encoded acker IdentityId. Used as
     *                       the dedupe key in `deliveredAckers`.
     * @param timestampSeconds acker's send time as Unix seconds.
     */
    fun onMessageAcked(
        groupIdHex: String,
        messageIdHex: String,
        ackerIdHex: String,
        timestampSeconds: Long,
    ) {
        // default no-op
    }

    /**
     * Outbound call signaling. The Rust call layer asks the app to
     * deliver `payload` to `recipientIdHex` over that peer's encrypted
     * 1:1 session — the same authenticated, forward-secret path as chat
     * messages. The peer feeds the bytes back via
     * `nativeHandleCallSignal`. Default no-op.
     *
     * @param recipientIdHex hex-encoded recipient IdentityId.
     * @param payload the opaque signaling frame to encrypt and send.
     */
    fun onCallSignal(recipientIdHex: String, payload: ByteArray) {
        // default no-op
    }

    /**
     * An inbound call invitation arrived and is ringing.
     *
     * @param callIdHex   hex-encoded CallId (16 bytes → 32 chars).
     * @param callerIdHex hex-encoded caller IdentityId.
     * @param callType    0=voice, 1=video, 2=group-voice,
     *                    3=group-video, 4=screen-share, 5=conference.
     */
    fun onIncomingCall(callIdHex: String, callerIdHex: String, callType: Int) {
        // default no-op
    }

    /**
     * A call's lifecycle state changed (e.g. ringing → active, ended,
     * a participant left, or an error). `state` is a short token.
     *
     * @param callIdHex hex-encoded CallId.
     * @param state     human-readable lifecycle token.
     */
    fun onCallStateChanged(callIdHex: String, state: String) {
        // default no-op
    }
}
