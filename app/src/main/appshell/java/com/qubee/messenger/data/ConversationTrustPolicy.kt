package com.qubee.messenger.data

import com.qubee.messenger.data.db.ConversationEntity
import com.qubee.messenger.state.TrustEvent
import com.qubee.messenger.state.TrustState
import com.qubee.messenger.state.TrustStateMachine
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

data class ConversationTrustUpdate(
    val state: TrustState,
    val subtitle: String,
    val previousPeerFingerprint: String?,
    val lastKeyChangeAt: Long,
    val sessionInvalidated: Boolean,
)

internal fun ConversationEntity.toTrustState(): TrustState = when {
    trustResetRequired -> TrustState.ResetRequired
    isVerified -> TrustState.Verified
    else -> TrustState.Unverified
}

internal fun TrustState.isVerifiedFlag(): Boolean = this == TrustState.Verified

internal fun TrustState.isTrustResetRequiredFlag(): Boolean = this == TrustState.ResetRequired

internal fun bundleFingerprintFromBase64(peerBundleBase64: String): String {
    if (peerBundleBase64.isBlank()) return "Peer bundle pending"
    return runCatching {
        val decoded = Base64.getDecoder().decode(peerBundleBase64)
        val json = JSONObject(String(decoded))
        json.optString("identityFingerprint").takeIf { it.isNotBlank() }
            ?: MessageDigest.getInstance("SHA-256").digest(decoded).take(12).joinToString("") { "%02x".format(it) }
    }.getOrElse {
        MessageDigest.getInstance("SHA-256").digest(peerBundleBase64.toByteArray()).take(12).joinToString("") { "%02x".format(it) }
    }
}

internal fun resolvePeerBundleTrust(
    existing: ConversationEntity?,
    incomingFingerprint: String,
    bundleChanged: Boolean,
    now: Long,
    defaultSubtitle: String,
): ConversationTrustUpdate {
    val currentState = existing?.toTrustState() ?: TrustState.Unverified
    val previousFingerprint = existing?.peerBundleBase64
        ?.takeIf { it.isNotBlank() }
        ?.let(::bundleFingerprintFromBase64)
    val event = when {
        existing == null || existing.peerBundleBase64.isBlank() -> null
        bundleChanged && previousFingerprint != incomingFingerprint -> TrustEvent.PeerFingerprintObservedChanged
        else -> TrustEvent.PeerFingerprintObservedSame
    }
    val transition = event?.let { TrustStateMachine.reduce(currentState, it) }
    val resolvedState = transition?.state ?: currentState
    return ConversationTrustUpdate(
        state = resolvedState,
        subtitle = when {
            transition?.warningRequired == true -> "Safety key changed · trust reset required"
            resolvedState == TrustState.Verified -> defaultSubtitle
            resolvedState == TrustState.ResetRequired -> "Safety key changed · trust reset required"
            else -> defaultSubtitle
        },
        previousPeerFingerprint = if (transition?.warningRequired == true) previousFingerprint else existing?.previousPeerFingerprint,
        lastKeyChangeAt = if (transition?.warningRequired == true) now else existing?.lastKeyChangeAt ?: 0L,
        sessionInvalidated = transition?.sessionInvalidated == true,
    )
}

internal fun resolveLocalVerification(conversation: ConversationEntity): ConversationTrustUpdate {
    val transition = TrustStateMachine.reduce(conversation.toTrustState(), TrustEvent.LocalVerified)
    return ConversationTrustUpdate(
        state = transition.state,
        subtitle = "Safety code verified · trust established",
        previousPeerFingerprint = conversation.previousPeerFingerprint,
        lastKeyChangeAt = conversation.lastKeyChangeAt,
        sessionInvalidated = transition.sessionInvalidated,
    )
}

internal fun resolveLocalTrustReset(conversation: ConversationEntity): ConversationTrustUpdate {
    val transition = TrustStateMachine.reduce(conversation.toTrustState(), TrustEvent.LocalReset)
    return ConversationTrustUpdate(
        state = transition.state,
        subtitle = "Trust reset locally · verify safety code again before trusting",
        previousPeerFingerprint = conversation.previousPeerFingerprint,
        lastKeyChangeAt = conversation.lastKeyChangeAt,
        sessionInvalidated = transition.sessionInvalidated,
    )
}
