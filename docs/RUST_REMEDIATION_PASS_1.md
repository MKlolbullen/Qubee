# Rust Remediation Pass 1

This pass fixes the most immediate structural and security issues in the active Rust path without pretending the protocol is suddenly finished.

## What changed

### 1. Removed the duplicate `src/lib` universe
The orphaned alternate library tree was removed so the crate has one active reality instead of two competing ones.

### 2. Hardened active identity state in memory
The live native identity state now stores private keys as binary arrays in the active process state instead of keeping the active copy as serialized JSON/base64 fields.

### 3. Replaced static session keys with advancing chain keys
The active session model now advances a send and receive chain per message and binds ciphertext to a message counter. This is still not a full double ratchet, but it is materially better than a static symmetric session.

### 4. Added replay/out-of-order rejection in the native core
Cipher envelopes now carry a session identifier and counter, and decrypt rejects replayed or out-of-order ciphertext instead of quietly accepting it.

### 5. Added session restore support
Session bundles can now be restored into active native state. This improves unlock/restart behavior and makes native session behavior testable.

### 6. Added structured JNI result APIs
The JNI layer now exposes `...Result` functions that return structured native results with error codes and payloads instead of only null arrays and booleans.

### 7. Tightened relay authentication semantics
The relay now validates that the authenticated bundle matches the claimed handle, device ID, and fingerprint before accepting the session.

### 8. Fixed arbitrary multi-device bundle selection
Peer bundle lookup now supports device-specific requests and returns a deterministic list of bundles instead of selecting a random `HashMap` value.

## What is still not fixed

- there is still no full Signal-style double ratchet
- there is still no post-quantum live path in the active crate
- relay-side namespace and device management still need a deliberate key rotation / re-link flow
- Kotlin still needs to adopt the structured JNI result APIs instead of relying on the old null-based ones

## Why this matters

The active Rust path is now less split-brained, less trusting of self-asserted relay identity, less dependent on static session keys, and more recoverable after process restart. That is real progress, even if the core protocol still needs deeper work.
