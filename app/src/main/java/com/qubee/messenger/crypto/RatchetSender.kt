package com.qubee.messenger.crypto

import com.qubee.messenger.data.repository.GroupRepository
import com.qubee.messenger.data.repository.PreferenceRepository
import javax.inject.Inject
import javax.inject.Singleton
import timber.log.Timber

/**
 * Send-side orchestration for the Stage 5 ratchet cutover, gated on
 * [PreferenceRepository.ratchetSendEnabled] (default off). All
 * cryptography stays in Rust; this class only sequences the calls:
 * probe the sender chain, fan out key distributions when nobody holds
 * the current chain, then hand back the encrypted frame for the
 * caller's persist-then-publish flow.
 *
 * Fail-closed: when the flag is on and the v3 path can't produce a
 * frame, the send FAILS — it never silently downgrades to the legacy
 * envelope, because a suppressible downgrade would let an adversary
 * strip forward secrecy by suppressing prekey bundles.
 */
@Singleton
class RatchetSender @Inject constructor(
    private val qubeeManager: QubeeManager,
    private val groupRepository: GroupRepository,
    private val preferenceRepository: PreferenceRepository,
) {

    fun enabled(): Boolean = preferenceRepository.ratchetSendEnabled()

    /** Encrypt a 1:1 text as a QUBEE_DMS frame, or null (fail-closed). */
    suspend fun encryptDirectText(peerIdHex: String, text: String): ByteArray? =
        qubeeManager.encryptDirectMessage(peerIdHex, text)

    /**
     * Encrypt a group text as a QUBEE_GMS v3 frame, fanning out sender
     * key distributions first when the chain probe says no member can
     * hold the current chain (first send, or the chain was wiped by a
     * rekey). Distribution delivery is per-member best-effort: a member
     * whose prekey bundle hasn't arrived yet can't receive the chain
     * and will fail to decrypt until the next fan-out reaches them.
     * TODO(two-device checklist): redeliver distributions to members
     * that missed the fan-out, mirroring the JoinAccepted/KeyDelivery
     * redelivery hardening tracked for phase 1.5.
     */
    suspend fun encryptGroupText(groupIdHex: String, selfIdHex: String?, text: String): ByteArray? {
        if (qubeeManager.ownSenderChainIteration(groupIdHex) <= 0L) {
            distributeSenderKey(groupIdHex, selfIdHex)
        }
        return qubeeManager.encryptGroupMessageV3(groupIdHex, text)
    }

    private suspend fun distributeSenderKey(groupIdHex: String, selfIdHex: String?) {
        val members = groupRepository.listGroupMembers(groupIdHex)
        if (members == null) {
            Timber.w("Sender-key fan-out skipped: no local view of group members")
            return
        }
        for (member in members) {
            if (!member.isActive || member.identityIdHex.equals(selfIdHex, ignoreCase = true)) continue
            val frame = qubeeManager.createDirectDistributionMessage(member.identityIdHex, groupIdHex)
            if (frame == null) {
                Timber.w(
                    "No ratchet session/bundle for %s — distribution deferred",
                    member.identityIdHex.take(8),
                )
                continue
            }
            if (!qubeeManager.sendP2PMessage(member.identityIdHex, frame)) {
                Timber.w("Distribution publish failed for %s", member.identityIdHex.take(8))
            }
        }
    }
}
