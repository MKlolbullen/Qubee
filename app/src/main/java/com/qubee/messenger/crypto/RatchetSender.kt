package com.qubee.messenger.crypto

import com.qubee.messenger.data.repository.GroupRepository
import com.qubee.messenger.data.repository.PreferenceRepository
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import timber.log.Timber

/**
 * Send-side orchestration for the Stage 5 ratchet cutover, gated on
 * [PreferenceRepository.ratchetSendEnabled] (default off). All
 * cryptography stays in Rust; this class only sequences the calls:
 * probe the sender chain, fan out key distributions to members that
 * still need the current chain, then hand back the encrypted frame
 * for the caller's persist-then-publish flow.
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

    /**
     * Members still owed the CURRENT sender chain, per group. Seeded
     * with the full active roster when a fresh chain is minted and
     * drained as distributions succeed; retried on every subsequent
     * send so a member whose prekey bundle arrives late gets the chain
     * as soon as we hear from them — without this, one deferred
     * distribution would lock that member out of the whole chain
     * (iteration > 0 skips the fan-out forever).
     * TODO(two-device checklist): persist across process restarts; an
     * app kill with entries pending currently drops them until the
     * next rekey mints a fresh chain.
     */
    private val pendingDistribution = mutableMapOf<String, MutableSet<String>>()
    private val pendingLock = Mutex()

    fun enabled(): Boolean = preferenceRepository.ratchetSendEnabled()

    /** Encrypt a 1:1 text as a QUBEE_DMS frame, or null (fail-closed). */
    suspend fun encryptDirectText(peerIdHex: String, text: String): ByteArray? =
        qubeeManager.encryptDirectMessage(peerIdHex, text)

    /**
     * Encrypt a group text as a QUBEE_GMS v3 frame. A fresh chain
     * (iteration <= 0: first send, or wiped by a rekey) seeds the
     * pending set with every active member; any still-pending members
     * are retried before each send. Members that keep failing (no
     * prekey bundle yet) stay pending and cannot decrypt frames sent
     * in the meantime — deliberate: blocking the whole group's sends
     * on one unreachable member would be a worse failure mode.
     */
    suspend fun encryptGroupText(groupIdHex: String, selfIdHex: String?, text: String): ByteArray? {
        pendingLock.withLock {
            val pending = pendingDistribution.getOrPut(groupIdHex) { mutableSetOf() }
            if (qubeeManager.ownSenderChainIteration(groupIdHex) <= 0L) {
                pending.clear()
                pending += activeMemberIds(groupIdHex, selfIdHex)
            }
            if (pending.isNotEmpty()) {
                deliverDistributions(groupIdHex, pending)
            }
        }
        return qubeeManager.encryptGroupMessageV3(groupIdHex, text)
    }

    private suspend fun activeMemberIds(groupIdHex: String, selfIdHex: String?): List<String> {
        val members = groupRepository.listGroupMembers(groupIdHex)
        if (members == null) {
            Timber.w("Sender-key fan-out: no local view of group members yet")
            return emptyList()
        }
        return members
            .filter { it.isActive && !it.identityIdHex.equals(selfIdHex, ignoreCase = true) }
            .map { it.identityIdHex }
    }

    /** Attempts delivery to every pending member, removing successes. */
    private suspend fun deliverDistributions(groupIdHex: String, pending: MutableSet<String>) {
        val delivered = mutableListOf<String>()
        for (memberIdHex in pending) {
            val frame = qubeeManager.createDirectDistributionMessage(memberIdHex, groupIdHex)
            if (frame == null) {
                Timber.w(
                    "No ratchet session/bundle for %s — distribution stays pending",
                    memberIdHex.take(8),
                )
                continue
            }
            if (qubeeManager.sendP2PMessage(memberIdHex, frame)) {
                delivered += memberIdHex
            } else {
                Timber.w("Distribution publish failed for %s — stays pending", memberIdHex.take(8))
            }
        }
        pending -= delivered.toSet()
    }
}
