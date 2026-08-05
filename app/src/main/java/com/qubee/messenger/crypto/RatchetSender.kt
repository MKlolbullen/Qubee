package com.qubee.messenger.crypto

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
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
     *
     * Persisted (JSON, via [PreferenceRepository]) so a process kill
     * with entries still pending doesn't strand those members until the
     * next rekey. Loaded lazily on first access.
     */
    private var pendingDistribution: MutableMap<String, MutableSet<String>>? = null
    private val pendingLock = Mutex()

    fun enabled(): Boolean = preferenceRepository.ratchetSendEnabled()

    private fun pending(): MutableMap<String, MutableSet<String>> {
        pendingDistribution?.let { return it }
        val loaded: MutableMap<String, MutableSet<String>> = runCatching {
            preferenceRepository.loadPendingDistribution()?.let { json ->
                val type = object : TypeToken<MutableMap<String, MutableSet<String>>>() {}.type
                Gson().fromJson<MutableMap<String, MutableSet<String>>>(json, type)
            }
        }.getOrNull() ?: mutableMapOf()
        pendingDistribution = loaded
        return loaded
    }

    private fun persistPending() {
        runCatching {
            preferenceRepository.savePendingDistribution(Gson().toJson(pendingDistribution))
        }.onFailure { Timber.w(it, "Failed to persist pending-distribution set") }
    }

    /** Encrypt a 1:1 text as a QUBEE_DMS frame, or null (fail-closed). */
    suspend fun encryptDirectText(peerIdHex: String, text: String): ByteArray? =
        qubeeManager.encryptDirectMessage(peerIdHex, text)

    /**
     * Retry every group's still-pending sender-key distributions.
     * Called when a peer's prekey bundle is newly installed (a member
     * we couldn't reach before may now be reachable), so a late joiner
     * gets the current chain without waiting for the next group send.
     * No-op when the flag is off or nothing is pending.
     */
    suspend fun redeliverPending() {
        if (!enabled()) return
        pendingLock.withLock {
            val map = pending()
            if (map.isEmpty()) return
            var changed = false
            for ((groupIdHex, members) in map) {
                if (members.isEmpty()) continue
                val before = members.size
                deliverDistributions(groupIdHex, members)
                if (members.size != before) changed = true
            }
            map.entries.removeAll { it.value.isEmpty() }
            if (changed) persistPending()
        }
    }

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
            val map = pending()
            val group = map.getOrPut(groupIdHex) { mutableSetOf() }
            if (qubeeManager.ownSenderChainIteration(groupIdHex) <= 0L) {
                group.clear()
                group += activeMemberIds(groupIdHex, selfIdHex)
            }
            if (group.isNotEmpty()) {
                deliverDistributions(groupIdHex, group)
            }
            if (group.isEmpty()) map.remove(groupIdHex)
            persistPending()
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
