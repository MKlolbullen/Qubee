# Qubee cryptography flow

Qubee is designed as a post-quantum safe end-to-end messenger where Android/Kotlin owns application orchestration and presentation, while the Rust core owns cryptographic authority.

The rule is simple:

> Kotlin may request cryptographic operations. Rust performs them.

Kotlin must never implement fallback cryptography, plaintext compatibility envelopes, or silently downgrade security when a JNI symbol is missing.

## Layer model

```mermaid
flowchart TD
    subgraph ANDROID["Android / Kotlin app layer"]
        UI["Compose UI\n- onboarding\n- contacts\n- chats\n- verification\n- group invites"]
        VM["ViewModels + repositories\n- ChatViewModel\n- MessageRepository\n- ContactRepository\n- GroupRepository"]
        ROOM["SQLCipher + Room\nlocal encrypted persistence\n- contacts\n- conversations\n- messages\n- trust state\n- peer/contact linkage"]
        QM["QubeeManager.kt\nJNI facade"]
    end

    subgraph JNI["JNI bridge"]
        JNIAPI["Native API boundary\nType conversion only\nNo cryptographic logic"]
    end

    subgraph RUST["Rust cryptographic core"]
        INIT["Core initialization"]
        ID["Identity subsystem"]
        VERIFY["Verification subsystem"]
        GROUP["Group protocol"]
        MSG["Message encryption"]
        FILE["File/binary encryption"]
        STORE["Secure storage"]
        NET["P2P transport integration"]
    end

    UI --> VM
    VM --> ROOM
    VM --> QM
    QM --> JNIAPI
    JNIAPI --> INIT
    JNIAPI --> ID
    JNIAPI --> VERIFY
    JNIAPI --> GROUP
    JNIAPI --> MSG
    JNIAPI --> FILE
    JNIAPI --> NET

    ID --> STORE
    VERIFY --> ID
    GROUP --> STORE
    MSG --> STORE
    FILE --> STORE
    NET --> MSG
    NET --> GROUP
```

## Responsibilities

### Android / Kotlin

Kotlin owns:

- UI and user flows.
- ViewModels and application state.
- Room-backed persistence for metadata, contacts, conversations, messages, and trust state.
- Calling `QubeeManager.kt` for cryptographic operations.
- Passing opaque encrypted bytes to transport.

Kotlin must not own:

- private identity keys.
- session secrets.
- group keys.
- post-quantum KEM private keys.
- message/file encryption logic.
- fallback crypto behavior.

### JNI

JNI owns:

- converting Kotlin types to Rust-compatible values.
- returning Rust results to Kotlin.
- surfacing failures explicitly.

JNI must not own:

- cryptographic policy.
- envelope parsing semantics.
- plaintext compatibility paths.

### Rust core

Rust owns:

- identity key generation.
- fingerprint generation.
- SAS generation.
- invite parsing and validation.
- group handshake verification.
- group key handling.
- message encryption/decryption.
- file/binary encryption/decryption.
- replay/timestamp checks.
- secure storage of cryptographic material.

## Identity creation flow

```mermaid
flowchart LR
    A["User creates identity"] --> B["Kotlin onboarding flow"]
    B --> C["QubeeManager.kt"]
    C --> D["JNI nativeCreateOnboardingBundle / nativeInitialize"]
    D --> E["Rust identity subsystem"]
    E --> F["Generate/load hybrid identity keypair"]
    F --> G["Compute public identity + fingerprint"]
    F --> H["Store private material in Rust secure storage"]
    G --> I["Return public metadata to Kotlin"]
    I --> J["Persist non-secret metadata"]
    J --> K["Display QR/deep link/fingerprint"]
```

Security invariant:

> Private identity material must remain inside Rust-controlled storage.

## Contact onboarding flow

```mermaid
sequenceDiagram
    participant A as Alice Android
    participant AR as Alice Rust Core
    participant B as Bob Android
    participant BR as Bob Rust Core

    A->>AR: nativeCreateOnboardingBundle(displayName, userId)
    AR->>AR: Build signed public identity bundle
    AR-->>A: qubee://identity/<token>
    A-->>B: QR / deep link
    B->>BR: nativeVerifyOnboardingLink(link)
    BR->>BR: Parse and validate bundle
    BR->>BR: Compute fingerprint
    BR-->>B: Parsed public identity
    B->>B: Store contact as Unverified
```

Imported contacts are not automatically verified. Import only proves the app parsed a public identity payload; it does not prove the user has authenticated that identity out-of-band.

## Fingerprint verification flow

```mermaid
flowchart LR
    A["Canonical public identity bytes"] --> B["Rust BLAKE3-style hash"]
    B --> C["Formatted fingerprint"]
    C --> D["Kotlin verification UI"]
    D --> E["User compares out-of-band"]
    E --> F{"Match?"}
    F -->|Yes| G["Trust state = Verified"]
    F -->|No| H["Trust state remains Unverified / Warning"]
```

Security invariant:

> Verified trust must only be granted after a user-visible verification ceremony.

## SAS verification flow

```mermaid
flowchart TD
    A["Alice public identity key"] --> C["Canonical ordering"]
    B["Bob public identity key"] --> C
    C --> D["Rust SAS derivation"]
    D --> E["Short Authentication String"]
    E --> F["Both users compare"]
    F --> G{"Codes match?"}
    G -->|Yes| H["Mark contact verified"]
    G -->|No| I["Do not trust contact"]
```

The SAS must be derived inside Rust from canonical public identity material. Kotlin displays the result; it does not derive it.

## Direct message send flow

```mermaid
sequenceDiagram
    participant UI as Android UI
    participant VM as Kotlin ViewModel/Repo
    participant JNI as QubeeManager/JNI
    participant R as Rust Core
    participant S as Secure Storage
    participant N as P2P Transport
    participant DB as SQLCipher Room

    UI->>VM: User sends plaintext
    VM->>JNI: encryptMessage(sessionId, plaintext)
    JNI->>R: nativeEncryptMessage
    R->>S: Load identity/session/group key
    R->>R: Encrypt payload into opaque envelope
    R-->>JNI: ciphertext envelope bytes
    JNI-->>VM: opaque bytes
    VM->>DB: Store outgoing message state
    VM->>JNI: sendP2PMessage(peerId, envelope)
    JNI->>R: nativeSendP2PMessage
    R->>N: Send opaque bytes
```

Message state should not become `Sent` merely because the user tapped send. The correct state transition is:

```text
Draft -> Encrypting -> EncryptedQueued -> Sending -> SentToTransport -> DeliveredToPeer -> Read
```

Failures should be explicit:

```text
FailedEncryption
FailedTransport
FailedDecryption
RejectedUntrustedSender
RejectedReplay
```

## Direct message receive flow

```mermaid
sequenceDiagram
    participant N as P2P Transport
    participant R as Rust Core
    participant JNI as QubeeManager/JNI
    participant VM as Kotlin MessageService/Repo
    participant DB as SQLCipher Room
    participant UI as Android UI

    N->>R: Incoming opaque bytes
    R->>R: Parse envelope
    R->>R: Check version/timestamp/replay
    R->>R: Resolve sender/session/group
    R->>R: Decrypt payload
    R-->>JNI: Plaintext + sender metadata
    JNI-->>VM: Message event
    VM->>DB: Persist message
    DB-->>UI: Observe new message
```

Security invariant:

> Rust parses and validates encrypted envelopes. Kotlin must not interpret cryptographic envelope internals.

## File/binary payload flow

For P1/P2, files/images/audio can be treated as binary payloads encrypted through the same Rust-owned envelope discipline used for messages.

```mermaid
flowchart TD
    A["File/image/audio bytes"] --> B["Kotlin reads bytes"]
    B --> C["QubeeManager.encryptFile(sessionId, bytes)"]
    C --> D["JNI nativeEncryptFile"]
    D --> E["Rust encrypts binary payload"]
    E --> F["Opaque encrypted envelope bytes"]
    F --> G["Kotlin stores attachment metadata"]
    G --> H["P2P sends opaque bytes"]
```

Receive path:

```mermaid
flowchart TD
    A["Incoming encrypted file envelope"] --> B["nativeDecryptFile"]
    B --> C["Rust parses and decrypts envelope"]
    C --> D["Return raw file bytes"]
    D --> E["Kotlin writes/renders attachment"]
```

Future dedicated file protocol should add:

- chunked encryption.
- per-file manifest.
- per-chunk nonce/authentication.
- resumable transfer.
- content hash.
- encrypted thumbnails.

## Group protocol flow

```mermaid
flowchart TD
    A["Create group"] --> B["Rust GroupManager"]
    B --> C["Provision group state/key material"]
    C --> D["Store group state"]
    D --> E["Create invite"]
    E --> F["Peer accepts invite"]
    F --> G["RequestJoin handshake"]
    G --> H["JoinAccepted response"]
    H --> I["MemberAdded broadcast"]
    I --> J["Roster/version update"]
    J --> K["Group message encryption ready"]
```

The group protocol is also useful as the current direct-message bridge substrate where one-to-one conversations map onto private session/group IDs.

## Group state sync flow

P2P broadcast is not durable. Members who are offline can miss membership updates. The group state sync flow lets a lagging member recover roster state.

```mermaid
sequenceDiagram
    participant B as Lagging member
    participant A as Current member

    B->>A: RequestStateSync(groupId, sinceVersion)
    A->>A: Verify requester is active member
    A->>A: Build active roster snapshot
    A-->>B: StateSyncResponse(roster, currentVersion)
    B->>B: Verify responder is active member
    B->>B: Merge roster snapshot
```

State sync does not automatically recover every missed group-key generation. A member may recover roster state but still fail decryption until key re-send/re-encapsulation exists. That failure is safer than guessing or silently weakening cryptography.

## Trust-state lifecycle

```mermaid
stateDiagram-v2
    [*] --> Unknown
    Unknown --> Unverified: imported identity/contact
    Unverified --> Verified: fingerprint/SAS match
    Verified --> KeyChanged: identity key changes
    KeyChanged --> Unverified: user acknowledges warning
    Unverified --> Verified: re-verification succeeds
    Unverified --> Blocked: user blocks
    Verified --> Blocked: user blocks
    Blocked --> Unverified: user unblocks
```

Hard invariant:

> Verified + changed identity key = KeyChanged, never Verified.

## Required diagnostics

Every build should be able to answer:

- Is Rust core initialized?
- What is the local identity fingerprint?
- Is the P2P node running?
- Which contacts are linked to which peer IDs?
- Which conversations have active session/group IDs?
- Did the last outbound message reach encrypted-envelope state?
- Did the last inbound message fail due to unknown sender, stale timestamp, replay, bad envelope, missing key, or trust-state rejection?

## Required test gates

The project should not be treated as cryptographically stable unless these pass:

```bash
bash scripts/check_jni_contracts.sh
bash scripts/audit_message_file_bridge.sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --features _typecheck_jni
cargo test
./gradlew :app:assembleDebug
```

And the manual two-device plan must pass:

```text
A -> B encrypted text
B -> A encrypted text
fingerprint/SAS verification
verified state persists after restart
identity reset downgrades trust
unknown sender / key-change is not silently trusted
```
