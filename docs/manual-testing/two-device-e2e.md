# Qubee two-device E2E manual test plan

This document is the minimum truth test for Qubee as a post-quantum safe end-to-end messenger.

The goal is not to test every UI button. The goal is to prove that two independent devices can create identities, discover each other, link peer identity to transport identity, exchange encrypted messages through the Rust core, verify trust, persist state, and detect dangerous key changes.

## Devices

Use two physical Android devices where possible.

- Device A: Alice
- Device B: Bob

Emulators are useful for UI testing, but physical devices are preferred for P2P/NAT/network behavior.

## Build

From repo root:

```bash
bash scripts/qubee_doctor.sh
./gradlew :app:assembleDebug
```

Install the same APK on both devices:

```bash
adb -s <device-a> install -r app/build/outputs/apk/debug/app-debug.apk
adb -s <device-b> install -r app/build/outputs/apk/debug/app-debug.apk
```

## Preconditions

- Both devices have network access.
- Both devices run the same build commit.
- Both devices start from a clean Qubee identity state.
- If needed, use Settings → Reset identity on both devices before testing.

## Test 1 — Identity bootstrap

### Steps

1. Launch Qubee on Device A.
2. Create identity for Alice.
3. Confirm onboarding completes.
4. Launch Qubee on Device B.
5. Create identity for Bob.
6. Confirm onboarding completes.

### Expected

- Each device has a local identity.
- Each device can display/share its identity QR/deep link.
- App restart does not force identity recreation.

### Failure notes

Record:

- device model
- Android version
- app commit
- logs around `nativeInitialize`

## Test 2 — Contact exchange

### Steps

1. On Device A, show Alice identity QR.
2. On Device B, scan Alice identity QR or open the identity deep link.
3. Confirm Alice appears in Bob contacts.
4. On Device B, show Bob identity QR.
5. On Device A, scan Bob identity QR or open the identity deep link.
6. Confirm Bob appears in Alice contacts.

### Expected

- Identity links parse successfully through Rust JNI.
- Contacts are inserted into encrypted Room storage.
- Contact identity fingerprints are visible in the verification UI.

### Failure notes

Check:

- `nativeVerifyOnboardingLink`
- contact insertion logs
- Room migration/database logs

## Test 3 — P2P node start and peer link

### Steps

1. Start/restart both apps.
2. Wait for P2P node startup on both devices.
3. Trigger contact/session setup if required by the UI.
4. Observe whether peer IDs are linked to contacts.

### Expected

- Rust core initializes on both devices.
- P2P service starts.
- Peer-to-contact linkage is stored.
- No contact is linked to the wrong peer ID.

### Failure notes

Capture:

- `nativeStartNetwork`
- `nativeRegisterCallback`
- `onPeerLinked`
- `MessageService` logs

## Test 4 — Text message A → B

### Steps

1. On Device A, open Bob chat.
2. Send: `hello from Alice <timestamp>`.
3. Observe send state on A.
4. Observe received message on B.

### Expected

- Message is encrypted by Rust before transport.
- Transport sends opaque encrypted bytes.
- Device B receives bytes through P2P callback.
- Rust decrypts message.
- Message is stored locally.
- UI updates without restart.

### Failure notes

Classify failure:

- encryption failed
- transport send failed
- inbound callback missing
- sender not linked
- decrypt failed
- Room insert failed
- UI observation failed

## Test 5 — Text message B → A

Repeat Test 4 in the opposite direction.

Expected result is symmetric behavior.

## Test 6 — App restart persistence

### Steps

1. Kill Qubee on both devices.
2. Relaunch Qubee on both devices.
3. Open the Alice/Bob chat on both devices.

### Expected

- Contacts persist.
- Conversation persists.
- Messages persist.
- Verification state persists.
- App does not create a new identity unexpectedly.

## Test 7 — Fingerprint verification

### Steps

1. Open Bob's contact verification screen on Device A.
2. Open Alice's contact verification screen on Device B.
3. Compare fingerprints out of band.
4. Mark contact verified on both devices.

### Expected

- Fingerprints match the expected identity values.
- Trust state changes from unverified to verified.
- Chat header/security sheet reflects verified status.
- Verified state persists after restart.

## Test 8 — SAS verification

### Steps

1. Generate SAS on Device A for Bob.
2. Generate SAS on Device B for Alice.
3. Compare codes out of band.
4. Mark verified if codes match.

### Expected

- Both devices produce the same SAS for the same identity pair.
- The SAS is stable across restarts for the same pair.
- A different identity pair produces a different SAS.

## Test 9 — Identity reset / key change warning

### Steps

1. Verify Alice and Bob.
2. On Device A, reset Alice identity.
3. Relaunch Alice app and create/regenerate identity if required.
4. Have Device B receive Alice's new identity/contact data or inbound message.

### Expected

- Bob must not silently keep Alice as verified.
- Bob should see a key-change / identity-changed warning.
- Bob must be forced to re-verify before returning to verified state.

### Security invariant

A changed identity key must never inherit previous verified trust.

## Test 10 — Negative sender/linkage test

### Steps

1. Introduce a third device or stale peer state if possible.
2. Try to deliver a message from an unknown or incorrectly linked peer.

### Expected

- Message is rejected or quarantined.
- UI does not show it as trusted contact content.
- Diagnostic logs explain the rejection reason.

## Evidence to capture

For every test run, capture:

- app commit SHA
- APK build variant
- device models
- Android versions
- network type
- adb logcat snippets
- screenshots of identity/fingerprint/SAS screens
- pass/fail table

## Pass criteria for milestone

Qubee passes the two-device E2E milestone only when all of these are true:

- A → B encrypted text works.
- B → A encrypted text works.
- Contact identity verification works.
- Verified trust persists after restart.
- Identity reset downgrades trust and requires re-verification.
- No plaintext compatibility crypto exists in Kotlin.
- JNI contract checker passes.
- Rust tests pass.
- Android debug APK builds.
