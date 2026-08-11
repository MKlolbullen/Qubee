# Security policy

Qubee is a **pre-alpha, research-grade post-quantum P2P messenger**.

The cryptographic primitives are not the only — or even the most likely — place for a serious defect. The highest-value attack surface is the glue around them: wire parsing, JNI, protocol state, persistence, libp2p routing, Android lifecycle, trust policy and the feature-gated calling stack.

> **Do not use Qubee for safety-of-life communications or high-risk operational traffic.**
> The project has not received an independent security audit.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected vulnerability.**

Preferred reporting path:

1. **GitHub private vulnerability report**
   <https://github.com/MKlolbullen/Qubee/security/advisories/new>
2. If GitHub private reporting is unavailable, contact the maintainer through the address published on the repository owner's GitHub profile.

If you need a fixed security contact and cannot reach the maintainer privately, open a public placeholder issue titled only **"request security contact"** without vulnerability details.

A dedicated PGP key/fingerprint may be added here when one is maintained for this project.

### What to include

A useful report contains:

- a clear description of the bug;
- the commit SHA and build type tested;
- the affected component;
- a minimal reproducer where practical;
- expected vs. observed behavior;
- your impact/exploitability assessment;
- whether the report has been shared elsewhere.

Good reproducers include a failing `cargo test`, crafted wire bytes, a small Android test, an `adb` procedure, or a deterministic state-machine trace.

### Response targets

| Stage | Target |
|---|---:|
| Acknowledge receipt | 72 hours |
| Initial triage / severity | 7 days |
| High / critical fix + disclosure plan | 30 days |
| Other accepted issues | 90 days |
| Public advisory | After a fix lands and an affected release is addressed |

These are targets rather than contractual SLAs; Qubee is maintained as a research project.

## In scope

The following are explicitly in scope:

- Rust core (`src/`) and public APIs;
- JNI boundary (`src/jni_api.rs` and the Kotlin `QubeeManager` contract);
- identity, onboarding and trust-state transitions;
- PQXDH-style prekey/session establishment;
- Double Ratchet state, replay handling and persistence;
- sender-key distribution, membership checks and rekey behavior;
- group/direct wire-format parsers;
- retry/ACK/crash-consistency behavior;
- libp2p transport configuration and application routing decisions;
- Android Room/SQLCipher persistence;
- Android Keystore / auth-bound key handling;
- app-lock behavior where it is intended to protect locked-device state;
- build/release scripts and GitHub Actions;
- feature-gated calling code, including signaling, JNI, call-state transitions, ICE/SDP handling and Android media plumbing.

### Calling is now in scope

Calling used to be a disconnected Rust experiment. That is no longer true.

The tree now contains:

- Rust call-state + WebRTC orchestration;
- ratchet-carried call signaling;
- JNI call controls and media-sample methods;
- Compose incoming/active call UI;
- microphone foreground-service plumbing;
- Android `AudioRecord` / Opus `MediaCodec` / `AudioTrack` scaffolding.

The `calling` Cargo feature is still **off by default** and the default release JNI library is built without it, so calling is not a normal shipped capability yet. Nevertheless, its attack surface is sufficiently integrated that security reports are welcome now.

Particularly interesting calling findings include:

- stale/replayed invitations;
- call-id or participant substitution;
- state confusion between overlapping calls;
- signaling that escapes the authenticated 1:1 session;
- unsafe ICE/SDP parsing or routing;
- media queue/resource exhaustion;
- media/key binding mistakes;
- JNI confusion or malformed callback data;
- permission/foreground-service failures that become privacy problems;
- teardown races leaving microphone/camera capture active.

## Generally out of scope

- Side-channel resistance inside upstream primitive implementations unless Qubee's use materially creates the problem.
- Vulnerabilities that require a device to already be rooted, fully compromised and unlocked, where the attacker can simply read process memory or instrument the application.
- Phishing/social engineering against the out-of-band verification ceremony itself.
- Bugs only reachable in legacy modules excluded from default builds (`hybrid_ratchet`, legacy `secure_message`, legacy `file_transfer`, legacy `audio`, `sas`, `oob_secrets`) unless they become reachable from a supported build configuration.
- Pure upstream WebRTC/libp2p defects with no Qubee-specific impact beyond the upstream issue. Qubee integration mistakes remain in scope.

## Current acknowledged limitations

These are security-relevant project limitations, but are not automatically vulnerabilities by themselves.

### 1. Forward-secret messaging is default-on but still soaking

`PreferenceRepository.ratchetSendEnabled()` currently defaults to `true`.

Outbound 1:1 traffic uses the `QUBEE_DMS` PQXDH + Double Ratchet path. Outbound group traffic uses sender keys, with keyed-selector **v5** as the current group emission format.

The emergency rollout flag remains as a temporary kill-switch. Compatibility paths also remain:

- older direct/group formats may still be accepted;
- sender-key v3 remains an inbound compatibility path;
- legacy v2 emission/reception has not yet been completely retired.

The physical-device runbook still calls for recorded release-build coverage across multiple OEMs. Treat the messaging design as **implemented and extensively host-tested, but not independently audited and not fully proven across every Android lifecycle/OEM condition**.

### 2. Deniability differs by protocol generation

The current ratcheted direct path authenticates messages/ACKs with keys derived from the session rather than long-term per-message identity signatures. That supports the intended deniable model.

Legacy signed-envelope messages are different: long-term hybrid signatures can make authorship cryptographically attributable. Any peer that still emits a legacy format should be treated as using the older non-deniable model.

### 3. Network metadata is not hidden by default

Qubee's direct transport does not provide IP anonymity.

Current metadata reductions include:

- anonymous gossipsub authorship;
- mDNS off by default;
- blinded rotating group topics;
- padding buckets on forward-secret paths;
- keyed-selector group formats that avoid a plaintext group id.

These measures do **not** prevent:

- direct peers learning network addresses;
- timing/volume correlation;
- infrastructure observing connection metadata;
- ICE/STUN/TURN metadata exposure when calling is enabled.

Tor and Nym are currently architectural/fail-closed foundations, not working anonymising transports.

### 4. Local protection depends on Screen Lock policy and process state

With Screen Lock disabled, Qubee permits headless/background operation using auth-free Android Keystore wrapping. That is an explicit availability/usability trade-off.

When Screen Lock is enabled, the app adds both a UI gate and auth-bound key handling intended to prevent a cold locked process from opening protected storage before biometric/device-credential authorization.

Caveats:

- a database connection that is already open in a live process is not equivalent to a cold locked process;
- Android API/OEM behavior differs;
- physical-device testing remains essential;
- full unlocked-device compromise is outside the threat model.

### 5. Rust keystore protection

The Rust keystores holding identity/group state are protected with a high-entropy passphrase supplied from Android's Keystore-backed layer. The Rust wrapping key uses Argon2id with a per-install salt and authenticated encryption.

The passphrase crosses JNI as mutable bytes, not as an immutable JVM `String`, and copies are zeroized where practical.

Older pre-alpha layouts used weaker migration-era wrapping choices; supported migrations are one-way toward the current format.

### 6. Calling is not a shipped security claim yet

The default native build runs Cargo without `--features calling`. Kotlin catches missing calling JNI symbols and fails closed.

When the feature is enabled for development, signaling is carried over the authenticated/encrypted direct-session path. The caller generates a fresh random per-call media root and carries it inside the encrypted invitation; both endpoints derive the same call media key using the call id and canonical participant pair.

Actual encoded media is currently handed to WebRTC, which negotiates DTLS-SRTP. The in-tree `MediaEncryption` helper should **not** be interpreted as a second active application-layer encryption layer unless the sample path is explicitly wired through it.

The Android audio pipeline is compile-verified scaffolding and still requires physical-device validation for codec availability, foreground-service rules, permission timing, audio routing and teardown behavior.

### 7. Database migrations are still pre-stable

Room has an explicit migration chain, but the project has not yet treated every schema snapshot as a stable release contract. Cross-version data survival before the first stable schema should be considered best-effort.

Schema JSON snapshots should be committed once generated and used as migration-review/test artifacts.

## Security invariants reviewers should challenge

High-value reports often demonstrate a violation of one of these:

1. **Rust remains the secret-state authority.**
2. **Both hybrid signature components verify or authentication fails.**
3. **Signed bytes are canonical, versioned and domain-separated.**
4. **Untrusted lengths are bounded before allocation.**
5. **Authentication succeeds before state mutation.**
6. **Removed members never receive newly rotated group material.**
7. **Identity-key changes never silently preserve Verified trust.**
8. **JNI errors fail closed without aborting the Android process.**
9. **Long-lived secrets do not cross JNI as immutable Java strings.**
10. **Wire-format changes require an explicit compatibility/version story.**
11. **Privacy-mode failure does not silently downgrade transport.**
12. **A retry reuses durable ciphertext and never advances the ratchet twice.**
13. **A frame for one session/group/call cannot be substituted into another.**
14. **Resource use from untrusted peers is bounded.**

## Disclosure policy

Qubee follows coordinated disclosure.

After an accepted issue affecting a release is fixed, the project may:

1. publish a GitHub Security Advisory with severity/CVSS;
2. credit the reporter unless anonymity is requested;
3. reference the fix in `CHANGELOG.md`;
4. request a CVE through GitHub when appropriate.

If credible active exploitation is discovered, disclosure and mitigation may be accelerated rather than waiting for the normal coordination window.

## Safe harbor for researchers

The project will not pursue legal action against good-faith researchers who:

- report through a private channel;
- avoid accessing/modifying data that is not theirs;
- avoid degrading service for other users;
- provide reasonable time to investigate/fix before public disclosure.

This is not currently a paid bug-bounty program.

## Cryptographic primitive sourcing

| Primitive | Rust crate | Purpose |
|---|---|---|
| ML-KEM-768 (FIPS 203) | `pqcrypto-mlkem` 0.1 | Post-quantum KEM component |
| ML-DSA-44 (FIPS 204) | `pqcrypto-mldsa` 0.1 | Post-quantum identity-signature component |
| Ed25519 | `ed25519-dalek` 2.2 | Classical identity-signature component |
| X25519 | `x25519-dalek` 2.0 | Classical prekey/ratchet agreement component |
| ChaCha20-Poly1305 | `chacha20poly1305` 0.10 | Authenticated encryption |
| BLAKE3 | `blake3` 1.x | Hashing / identifiers / derivation support |
| HKDF / SHA-2 | `hkdf` / `sha2` | Key derivation |
| Argon2id | `argon2` | Rust keystore wrapping KDF |

`Cargo.lock` is committed. CI runs RustSec-oriented auditing and an additional OSV sweep so the dependency review is not limited to one advisory database.
