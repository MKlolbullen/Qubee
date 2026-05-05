# Qubee protocol map

This document maps Qubee subsystems to the cryptographic protocols and primitives they are allowed to use.

The most important boundary:

```text
Android/Kotlin = orchestration, UI, persistence metadata
JNI = strict native boundary
Rust = cryptographic protocol authority
P2P transport = opaque ciphertext carrier
```

## Protocol map overview

| Area | Protocol / primitive | Implemented in |
|---|---|---|
| Identity keys | Hybrid classical + post-quantum signature identity | Rust |
| PQ signatures | ML-DSA / Dilithium-family | Rust |
| Classical signatures | Ed25519-style companion identity | Rust |
| KEM / key establishment | ML-KEM / Kyber-family | Rust |
| Fingerprints | BLAKE3 over canonical identity bytes | Rust |
| SAS | BLAKE3 over ordered identity keys | Rust |
| Group invite | Signed invite token / deep link | Rust |
| Group join | Signed RequestJoin / JoinAccepted / MemberAdded | Rust |
| Group key delivery | PQ KEM encapsulation | Rust |
| Message payloads | Rust encrypted envelope, AEAD-style | Rust |
| File payloads | Rust encrypted binary envelope | Rust |
| Transport | libp2p / opaque ciphertext routing | Rust + Kotlin orchestration |
| Local DB | SQLCipher-backed Room metadata/persistence | Kotlin/Android |
| JNI | Native function boundary only | Kotlin + Rust |

## Identity protocol

Used for:

- local device/user identity.
- onboarding bundles.
- contact fingerprints.
- SAS derivation input.
- key-change detection.

Primitive stack:

```text
Hybrid identity
├── Classical signature key
│   └── Ed25519-style identity companion
└── Post-quantum signature key
    └── ML-DSA / Dilithium-family identity component
```

Allowed Rust responsibilities:

- generate identity keys.
- load identity keys.
- serialize public identity material.
- compute identity fingerprint.
- sign identity/onboarding bundles.
- verify identity/onboarding bundles.

Forbidden Kotlin behavior:

- generating private identity keys.
- storing private identity keys directly.
- replacing Rust fingerprint calculation.
- treating imported contact identity as verified.

Relevant JNI:

```text
nativeInitialize
nativeResetIdentity
nativeCreateOnboardingBundle
nativeLoadOnboardingBundle
nativeVerifyOnboardingLink
```

## Verification protocol

Used for:

- fingerprint comparison.
- SAS comparison.
- manual trust ceremony.
- verified/unverified/key-changed state transitions.

Primitive stack:

```text
Fingerprint = formatted BLAKE3-style digest over canonical identity bytes
SAS = short code derived from both parties' canonical public identity material
```

Trust-state rules:

```text
Unknown -> Unverified       when contact is imported
Unverified -> Verified      only after fingerprint/SAS match
Verified -> KeyChanged      when identity key changes
KeyChanged -> Unverified    after user acknowledges warning
Unverified -> Verified      only after re-verification
```

Hard invariant:

```text
Verified + changed identity key = KeyChanged, never Verified
```

Relevant JNI:

```text
nativeVerifyIdentityKey
nativeGenerateSAS
nativeGetFingerprint / equivalent
nativeInspectMessageSender / equivalent
```

## Onboarding protocol

Used for:

- identity QR code.
- identity deep link.
- first contact import.

Wire concept:

```text
qubee://identity/<token>
```

Payload should contain:

- public identity material.
- display metadata.
- canonical fingerprint/hash.
- signature/proof over the bundle.

Flow:

```text
create local identity
-> build signed public onboarding bundle
-> encode as QR/deep link
-> peer scans
-> Rust parses and validates
-> Kotlin stores contact as Unverified
```

Relevant JNI:

```text
nativeCreateOnboardingBundle
nativeVerifyOnboardingLink
```

## Group invite protocol

Used for:

- inviting a peer into a group.
- joining a group by QR/deep link.

Wire concept:

```text
qubee://invite/<token>
```

Payload should contain:

- group id.
- inviter identity.
- expiration.
- optional max uses.
- group/member cap metadata.
- invite fingerprint/hash.
- signature/authenticity data.

Relevant JNI:

```text
nativeCreateGroup
nativeCreateGroupInvite
nativeParseInviteLink
nativeAcceptInvite
nativeListAcceptedInvites
```

## Group join protocol

Used for:

- admitting a new member.
- securely delivering group key material.
- updating group roster state.

Handshake messages:

```text
RequestJoin
├── group_id
├── invitation_code
├── joiner_public_key
├── joiner_display_name
├── joiner_kyber_pub / ML-KEM public key
└── hybrid signature

JoinAccepted
├── group_id
├── inviter/admin identity
├── encrypted group key material
├── membership metadata
└── hybrid signature

MemberAdded
├── group_id
├── new member identity
├── new member KEM public key
├── version
└── hybrid signature
```

Protocols used:

- ML-KEM / Kyber-family for key encapsulation to new member.
- ML-DSA / Dilithium-family for PQ authenticity.
- Classical signatures for hybrid identity authenticity.
- BLAKE3-style hashing for canonical hashes/fingerprints.

## Group state sync protocol

Used for:

- recovering roster state after offline periods.
- converging group membership state when broadcast messages were missed.

Messages:

```text
RequestStateSync
├── group_id
├── requester_id
├── since_version
└── timestamp

StateSyncResponse
├── group_id
├── responder_id
├── requester_id
├── active roster snapshot
├── current_version
└── timestamp
```

Security rules:

- requester must still be an active member.
- responder must be an active member.
- response must be addressed to the requester.
- snapshots update roster state only.
- snapshots do not magically recover missed key rotations.

## Message encryption protocol

Used for:

- direct text messages.
- group text messages.
- binary payloads until a dedicated file protocol exists.

Envelope concept:

```text
message envelope
├── magic/version prefix
├── group/session id
├── sender identity id
├── timestamp
├── generation / key version
├── nonce
├── ciphertext
├── authentication tag
└── sender authentication metadata
```

Required behavior:

- `nativeEncryptMessage` returns non-empty opaque envelope bytes.
- encrypted envelope must not equal plaintext.
- `nativeDecryptMessage` returns the original plaintext and sender metadata.
- stale/replayed/invalid envelopes must fail closed.

Relevant JNI:

```text
nativeEncryptMessage
nativeDecryptMessage
nativeSendGroupMessage
```

Recommended state machine:

```text
Draft
-> Encrypting
-> EncryptedQueued
-> Sending
-> SentToTransport
-> DeliveredToPeer
-> Read
```

Failure states:

```text
FailedEncryption
FailedTransport
FailedDecryption
RejectedUntrustedSender
RejectedReplay
RejectedBadEnvelope
RejectedUnknownSession
```

## File / binary payload protocol

Used for:

- files.
- images.
- audio.
- arbitrary binary payloads.

Current acceptable P1/P2 behavior:

```text
raw bytes -> Rust encrypted envelope -> opaque ciphertext bytes
```

Required behavior:

- `nativeEncryptFile` returns non-empty opaque envelope bytes.
- encrypted envelope must not equal raw file bytes.
- `nativeDecryptFile` returns exact original bytes.

Relevant JNI:

```text
nativeEncryptFile
nativeDecryptFile
```

Future dedicated file protocol:

```text
file manifest
├── file id
├── encrypted filename / metadata
├── total size
├── content hash
├── chunk size
├── chunk count
└── per-chunk descriptors

chunk envelope
├── file id
├── chunk index
├── nonce
├── ciphertext
└── authentication tag
```

Future requirements:

- resumable transfer.
- per-chunk authentication.
- encrypted thumbnails.
- streaming decrypt.
- local size limits and DoS protections.

## Transport protocol

Used for:

- peer discovery/routing.
- sending opaque ciphertext.
- receiving opaque ciphertext.
- emitting callbacks to Android.

Expected transport stack:

```text
libp2p
├── peer id / routing identity
├── direct peer messaging or request-response
├── gossipsub-style group fanout
└── network callbacks into Android
```

Transport security rule:

```text
Transport peer id is not the same as Qubee cryptographic identity.
```

The app must maintain explicit linkage:

```text
Contact identity id <-> transport peer id
```

If linkage changes unexpectedly, diagnostics and trust-state checks must fire.

Relevant JNI:

```text
nativeStartNetwork
nativeSendP2PMessage
nativeRegisterCallback
```

## Local persistence protocol

Used for:

- contacts.
- conversations.
- message history.
- trust state.
- peer/contact linkage.
- UI state.

Storage stack:

```text
SQLCipher + Room
```

Allowed contents:

- public contact identity material.
- fingerprints.
- trust state.
- message plaintext after local decrypt, if the product accepts local readable history.
- message encrypted envelope metadata.
- delivery states.
- peer linkage.

Not allowed:

- Rust private identity keys.
- Rust session secrets.
- group keys.
- raw KEM private keys.

## JNI contract gates

Every JNI method Kotlin declares must have a matching Rust export.

Checked by:

```bash
bash scripts/check_jni_contracts.sh
bash scripts/audit_message_file_bridge.sh
```

Message/file P0 symbols:

```text
nativeEncryptMessage
nativeDecryptMessage
nativeEncryptFile
nativeDecryptFile
```

The CI must fail if these drift.

## Semantic smoke tests

Rust-side semantic smoke tests must prove:

```text
nativeEncryptMessage core path -> non-empty envelope
nativeDecryptMessage core path -> plaintext round-trip
nativeEncryptFile core path -> non-empty envelope
nativeDecryptFile core path -> byte-exact round-trip
```

The current Rust-side smoke test validates core envelope semantics without instantiating a JVM. Full JNI runtime testing remains a separate Android/instrumentation layer.

## Product security invariants

Qubee must preserve these invariants:

1. Rust is the cryptographic authority.
2. Kotlin never performs fallback crypto.
3. JNI drift fails CI.
4. Imported contact is unverified by default.
5. Verified identity key changes downgrade trust.
6. Transport carries opaque encrypted bytes only.
7. Message/file encryption returns opaque envelopes, not plaintext wrappers.
8. Decryption failures are explicit and diagnosable.
9. Replay/stale envelopes are rejected.
10. Two-device E2E testing is required before calling a milestone complete.
