package com.qubee.messenger.crypto

import com.qubee.messenger.model.InvitePreview
import com.qubee.messenger.model.InviteShareBundle
import com.qubee.messenger.model.NativeBridgeStatus

interface CryptoEngine {
    fun status(): NativeBridgeStatus
    fun initializeIfPossible(): NativeBridgeStatus
    fun createIdentity(displayName: String): IdentityMaterial
    fun restoreIdentity(identity: IdentityMaterial): Boolean
    fun signRelayChallenge(identity: IdentityMaterial, challenge: String, relaySessionId: String): String?
    fun exportInvite(identity: IdentityMaterial): InviteShareBundle
    fun inspectInvitePayload(payloadText: String): InvitePreview
    fun computeSafetyCode(identity: IdentityMaterial, peerPublicBundleBase64: String): String
    fun createSession(
        conversationId: String,
        peerHandle: String,
        selfPublicBundleBase64: String,
        peerPublicBundleBase64: String,
    ): SessionMaterial
    fun acceptSessionBootstrap(
        conversationId: String,
        peerHandle: String,
        bootstrapPayloadBase64: String,
    ): SessionMaterial?
    fun encryptMessage(session: SessionMaterial, plaintext: String): EncryptedPayload
    fun decryptMessage(session: SessionMaterial, payload: EncryptedPayload): String
    fun generateDemoPeerBundle(seed: String): String
    fun deriveBootstrapToken(relayHandle: String, deviceId: String, identityFingerprint: String): String
}
