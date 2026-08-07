# Outbound crash consistency

The system that sends one message crosses four trust/durability domains
that are **not** one transaction:

```text
Room  ↔  Kotlin repo/VM  ↔  JNI  ↔  Rust ratchet keystore  ↔  network
```

A process death (Doze kill, OOM, crash, reboot) can land between any two
steps. The dangerous class is **the ratchet state advancing while the
durable outbound state doesn't** — or the inverse. This doc pins the
ordering invariants and the recovery so every death point has defined
semantics.

## The two failure classes

- **Key reuse (catastrophic).** If a ciphertext escapes the device but the
  ratchet advance that produced it is *not* durable, a relaunch replays
  the same chain position → the next send reuses a message key/nonce,
  breaking the AEAD and forward secrecy. This must be impossible.
- **Silent message loss (a reliability bug).** If the ratchet advances and
  the ciphertext is produced but no durable record survives, the message
  vanishes with no trace while the receiver just sees a skipped counter.
  Not a security hole, but unacceptable UX.

## Ordering invariants

1. **Ratchet advance is durable before the ciphertext is exposed.**
   Enforced in Rust: `encrypt_direct` / `encrypt_sender_key_message`
   advance the chain, `store_session` / `store_own_state` persist it, and
   only *then* is the ciphertext returned. If the persist fails they
   return `Err` with no ciphertext. So a crash after the caller holds a
   ciphertext can never revert the ratchet → **no key reuse**, ever.
   Locked by `tests/ratchet_cutover_e2e.rs`
   (`crash_after_advance_never_reuses_*`,
   `sends_straddling_a_restart_occupy_distinct_positions`).
2. **Plaintext is durable before the encrypt that advances the ratchet.**
   The `PREPARED` row (below) — closes the silent-loss window.
3. **Ciphertext is durable before it is transmitted.** The `Message` row
   carries `wireBytes` + `wireId` and is saved before `sendP2PMessage` /
   `publishGroupFrame`.
4. **Retransmit is idempotent.** Retries re-publish the *same* stored
   `wireBytes` (same `wireId`); receivers dedupe/replay-guard. A retry is
   never a re-encrypt, so one message never advances the ratchet twice.

## The state machine

`MessageStatus`, in send order:

```text
PREPARED → SENDING → SENT → DELIVERED
   │          │        │
   └──────────┴────────┴──► FAILED   (fail-closed / budget exhausted)
```

| State | Meaning | Durable? |
|---|---|---|
| `PREPARED` | plaintext + intent written; ratchet not yet touched | ✔ text |
| `SENDING`  | encrypted; ciphertext (`wireBytes`,`wireId`) queued; owned by the retry loop | ✔ ciphertext |
| `SENT`     | handed to the network at least once; still retried until ack | ✔ |
| `DELIVERED`| a `MessageAck` landed (`applyAck`) | ✔ terminal |
| `FAILED`   | encrypt failed (fail-closed) or retry budget spent | ✔ terminal |

Send path (`ChatViewModel.sendMessage`): write `PREPARED` → encrypt (Rust
advances + persists) → replace the row with `SENDING` + ciphertext →
publish → `SENT`/`FAILED`. Acks flip `SENDING`/`SENT` → `DELIVERED`.

## Recovery per death point

| Crash between… | On restart |
|---|---|
| before `PREPARED` write | nothing sent, nothing lost — user simply didn't send |
| `PREPARED` write and `SENDING` | row lingers in `PREPARED`; startup recovery flips it to `FAILED` (`MessageDao.failStalePreparedOutbound`), text preserved, one-tap resend. The ratchet may have advanced (a skipped counter the receiver tolerates) — never reused |
| `SENDING` write and the publish→`SENT`/`FAILED` update | row lingers in `SENDING` with durable ciphertext; the retry loop only reclaims `SENT`, so startup recovery promotes it to `SENT` (`MessageDao.recoverOrphanedSendingOutbound`). The retry loop then re-publishes the same wire idempotently |
| `SENT` and ack | ciphertext is durable; the retry loop re-publishes the same wire idempotently until ack or budget |
| after `DELIVERED` | terminal, pruned |

Recovery runs once at `MessageService` start, before the retry loop. A
genuinely in-flight `PREPARED` row only exists within a single send
coroutine, which transitions it before recovery could touch it.

## Deliberately deferred

Auto-**re-encrypt** of a `PREPARED` orphan (silently resending it without
user action) is a future refinement. The current guarantee is the one
that matters: **no key reuse, and no silent loss** — a `PREPARED` orphan
always surfaces as a resendable `FAILED` message. Tracked under the
v0.2.0 ratchet-cutover milestone (#47).
