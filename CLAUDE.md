# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Qubee is an Android + Rust secure messaging application. It combines:
- An **Android app shell** in Kotlin/Jetpack Compose (`app/`)
- A **native Rust cryptography core** exposed via JNI (`src/`)
- A **reference relay server** for bootstrap and recovery (`src/bin/qubee_relay_server.rs`)

The project is pre-production. The critical concern throughout the codebase is ensuring the **native Rust path** is always used for production crypto, and that preview/demo-era shell crypto is never mistaken for the trusted path.

## Build Commands

### Rust

```bash
# Build all Android JNI targets (runs prerequisite checks)
./build_rust.sh

# Manual single-target build
cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release

# Rust tests
cargo test

# Run relay server (no TLS)
cargo run --bin qubee_relay_server
```

Requires: Rust 1.88+, `cargo-ndk`, `ANDROID_NDK_HOME` set, Android targets installed (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android`).

### Android

Build via Android Studio (SDK 34, Java 17). Gradle sync is required after Rust library changes. The debug relay URL defaults to `ws://10.0.2.2:8787/ws` (Android emulator localhost).

```bash
# Lint / check (from repo root)
./gradlew lint
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease
```

### Relay with TLS

```bash
export QUBEE_RELAY_BIND=0.0.0.0:8787
export QUBEE_RELAY_TLS_CERT_PATH=/path/to/fullchain.pem
export QUBEE_RELAY_TLS_KEY_PATH=/path/to/privkey.pem
cargo run --bin qubee_relay_server
```

## Repository Structure

```
src/                        # Rust crate (qubee_crypto)
  lib.rs                    # Module declarations — read this first
  native_contract.rs        # Core production session/message path (alpha spine)
  jni_api.rs                # JNI bridge (Android target only)
  hybrid_ratchet.rs         # Legacy ratchet (pre-native_contract path)
  relay_protocol.rs         # Relay wire protocol
  relay_security.rs         # Relay TLS / rate limiting
  crypto/                   # Crypto support: enhanced_ratchet, identity
  security/                 # secure_keystore, secure_memory, secure_rng
  testing/                  # security_tests.rs
  audit/                    # security_auditor.rs
  bin/qubee_relay_server.rs # Reference relay server

app/src/main/appshell/java/com/qubee/messenger/
  crypto/
    CryptoEngine.kt         # Interface defining the crypto contract
    QubeeManager.kt         # Native bridge orchestration
    RelayCryptoEngine.kt    # Relay-side engine
    ConversationTrustPolicy.kt
  core/nativebridge/
    QubeeNativeBridge.kt    # Kotlin ↔ Rust JNI declarations
  data/
    MessengerRepository.kt  # Central data access layer
    QubeeServiceLocator.kt  # Dependency wiring
    db/                     # Room entities + DAO + SecureDatabaseFactory
  model/                    # UI/app data models
  network/p2p/              # Transport layer: WebRTC, BLE, Wi-Fi Direct, relay, Tor, bootstrap
  security/
    AppKeyManager.kt        # Android Keystore operations
    DatabasePassphraseManager.kt
    KillSwitch.kt
  ui/
    screens/                # All Compose screens
    theme/
  service/                  # Foreground/background node service
  state/                    # App state
```

## Architecture

### Layer separation

1. **Rust core** owns all trusted cryptographic operations. `native_contract.rs` is the production path. Modules named `hybrid_ratchet`, `dilithium_identity`, `secure_message` are legacy pre-native_contract code — they exist but must not be used as the production path.

2. **JNI boundary** (`jni_api.rs` ↔ `QubeeNativeBridge.kt`) is intentionally thin. Kotlin holds opaque session handles (base64 blobs); the Rust side owns ratchet state. Kotlin must never reconstruct cryptographic state.

3. **`CryptoEngine` interface** (`crypto/CryptoEngine.kt`) is the contract the Android layer programs against. `QubeeManager` delegates to the native bridge. `RelayCryptoEngine` is the relay-path implementation.

4. **`MessengerRepository`** is the single data access point. It coordinates the `CryptoEngine`, Room DB (`QubeeDao`/`QubeeDatabase`), and the transport/dispatch layer.

5. **Transport layer** (`network/p2p/`) is separate from the messaging protocol. `HybridEnvelopeDispatcher` routes encrypted envelopes over the preferred live path (WebRTC) with relay/bootstrap fallback. Transport and message semantics are intentionally kept separate.

6. **Room DB** uses `SecureDatabaseFactory` (SQLCipher seam). DB passphrase is managed by `DatabasePassphraseManager` using Android Keystore via `AppKeyManager`. The DB is only opened after unlock.

### Critical invariant

The production crypto path is: `native_contract.rs` → `jni_api.rs` → `QubeeNativeBridge.kt` → `QubeeManager` → `MessengerRepository`. Any code path that bypasses the native layer for real message encryption is considered a security defect.

## Key Design Decisions

- `lib.rs` marks `pub mod network` as quarantined (libp2p API mismatch) — do not uncomment without updating the libp2p API.
- The `DEFAULT_RELAY_URL` is a `BuildConfig` field in `app/build.gradle`, not hardcoded in Kotlin.
- `src/main` uses a custom `sourceSets` block pointing to `appshell/` — the standard `src/main/java` path is not used.
- Android `minSdk` is 26 (Android 8.0).

## Protocol and Design Docs

Key docs for understanding system-level decisions:
- `docs/JNI_BRIDGE_CONTRACT.md` — rules for the Rust/Kotlin boundary
- `docs/PROTOTYPE_TO_PRODUCTION_GAP.md` — what is and isn't production-ready
- `docs/protocol/` — native-api, identity-bundle, message-envelope, session-state, trust-state-machine, device-linking
- `docs/AUDIT_REMEDIATION_PASS*.md` — history of security hardening passes
