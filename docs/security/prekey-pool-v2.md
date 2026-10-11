# ID-addressed prekey pools and rotation

This is Qubee's hybrid X3DH-style setup, not a claim of Signal PQXDH interoperability or a completed security audit.

## Implemented policy

| Boundary | Policy |
| --- | --- |
| Published pool | At most 32 distinct random 128-bit IDs, each covering its own one-time X25519 key and ML-KEM-768 encapsulation key |
| Signature | Hybrid identity signature binds publisher, deniable identity, epoch, signed prekey, creation/publication times and the complete pool under `qubee_prekey_pool_v2` |
| Selection | Chosen ID and epoch bind into an additional HKDF step with the conversation identities; a pool initial must use a one-time pair |
| Local reservation | Sender reserves an ID in the same transaction as session creation and pending initial; reset/republication cannot clear that epoch's reservation ledger |
| Recipient consumption | Deletes only the selected X25519/ML-KEM pair after successful initial AEAD decryption; session, pair deletion and replay marker commit together |
| Rotation | New X25519 signed prekey and new pool at 7 days; identity keys and existing sessions stay stable |
| Retirement | Old epoch secrets retained at most 30 days plus 60 seconds after the scheduled rotation boundary; long suspension does not restart that clock |
| Bounds | At most 8 retained epochs, 32 live pairs per epoch, 128 IDs ever issued per epoch; exhaustion fails closed and needs publication/rotation |
| Freshness | Cached publication at most 30 days old, at most 60 seconds ahead of the local clock; persistent local `last_seen` rejects clock rollback beyond 60 seconds during pool management |
| Scheduling | Existing Android network-service publication on start and every 30 minutes triggers replenishment, rotation and pruning; execution depends on Android scheduling |

Each consumed pair is removed from live encrypted-keystore state. This does not promise physical erasure from backups, filesystem snapshots, storage hardware or memory owned by third-party cryptographic implementations. A restored old keystore can roll state back; the local timestamp check is not hardware-backed anti-rollback or a trusted clock.

## Wire and storage migration

`GroupHandshake::PrekeyPool` is appended at enum tag 13 without changing earlier tags. Pool initials use `QUBEE_DMS\x03` and explicitly carry an epoch/ID selection. The receiver and Android dispatcher recognize both v2 and v3. Established messages continue using the unchanged v2 envelope; session and pending-initial storage layouts remain intact, with a separate pending-selection marker for pool setup.

First pool creation imports the existing deniable X25519 identity from the v1 bundle. The legacy secret bundle is retained for a bounded migration window of 30 days plus 60 seconds from migration, then deleted during successful pool maintenance. It cannot be regenerated while pool state exists. Existing sessions keep working. After retirement, new setup with a legacy-only peer fails and requires a peer upgrade. Both phones should run this version for a new pool-based conversation.

Once a signed pool is cached, a legacy bundle cannot replace it. Invalid, expired or exhausted pools never cause a silent legacy/no-OTP fallback. Legacy-only contacts can still establish legacy sessions during the migration window; those setups do not acquire the new pool guarantees. Signing identity keys are not automatically rotated: identity replacement requires the existing contact-verification/trust-change flow.

## Decentralized allocation limit

Publishing a list does not globally reserve its entries. Two independent initiators can pick the same public pair. This device avoids local reuse, and the recipient accepts that pair only once; another initial using it fails closed and requires fresh publication plus a new setup attempt. Rotation also bounds secret lifetimes. A relay/reservation protocol that guarantees unique allocation across senders remains separate work. There is no automatic collision retry or reset of a working conversation in this change.

Epoch IDs and selected random prekey IDs appear on first-message headers. They reveal protocol version and can correlate repeated pending initials. Public signed-prekey publications and initial ratchet keys already permit linkage. This change does not hide timing, network addresses, topic membership or global traffic correlation.

## Verification

Host regression coverage includes migration identity preservation, reload, independent selected pairs, failed/tampered/replayed initials leaving durable state unchanged, replenishment without ID reuse, rotation boundaries, delayed initials, expiry after long suspension, existing sessions after pruning, local reservation exhaustion, downgrade/rollback rejection and selection KDF binding. Wire tests pin the new enum tag, canonical layout and v3 extension, while preserving v2 vectors; parser tests cover truncation, trailing bytes and arbitrary v3 data.

Physical Samsung results are not established by those tests. Use the acceptance runbook with two actual devices and the exact APK/source/signing identity recorded.

References: [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/) and [X3DH](https://signal.org/docs/specifications/x3dh/). These inform the lifecycle policy; Qubee's wire/KDF and decentralized distribution are its own protocol.
