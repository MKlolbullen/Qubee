package com.qubee.messenger.data.repository.database.dao

/**
 * Outcome of `MessageDao.applyAckTransactional`. Lifted out of the
 * DAO so the repository layer can pattern-match without importing
 * Room internals.
 *
 * `MessageRepository.applyAck` collapses this back into a `Boolean`
 * for the existing call site; richer call sites (e.g. a future
 * "delivered to N of M" badge) can branch on the variant.
 */
sealed class ApplyAckResult {
    /** No row matched the given `wireId`. */
    object NotFound : ApplyAckResult()

    /** Acker was already in `deliveredAckers` — idempotent re-delivery. */
    object AlreadyApplied : ApplyAckResult()

    /** Row updated; status moved to DELIVERED unless already READ. */
    object Applied : ApplyAckResult()
}
