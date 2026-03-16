# Qubee

Qubee is an experimental **Android + Rust secure messaging application** that is being hardened toward a real-world, hybrid post-quantum-capable messenger.

The repository combines three major layers:

- an **Android app shell** written in Kotlin/Jetpack Compose
- a **native Rust cryptography core** exposed through JNI
- a **reference relay / transport stack** used for bootstrap, recovery, and protocol iteration

This project is no longer just a UI prototype. It contains real application plumbing for unlock flows, encrypted local persistence, trust state, connectivity diagnostics, QR bootstrap, multi-device state, relay recovery, and a progressively hardened native session path.

That said, Qubee is still **pre-production**. It should be treated as a serious work-in-progress, not as a finished, audited, formally verified messenger.

---

## Current state

### What exists

- Android app shell using **Jetpack Compose**
- Rust shared library for JNI-backed cryptographic operations
- Room-based local persistence and app state plumbing
- Android Keystore / unlock scaffolding
- QR invite bootstrap and trust verification surfaces
- Multi-device state, reconnect reconciliation, and transport diagnostics
- WebRTC-oriented transport scaffolding and relay-assisted fallback
- A native hybrid session bootstrap path intended to replace legacy session setup
- Relay hardening work including optional TLS and rate limiting

### What is still not done enough to claim production readiness

- full on-device verification of the native hybrid path
- end-to-end validation of the ratcheting live message path across real devices
- hard removal or full quarantine of preview-only shell crypto from production builds
- final relay hardening, deployment, and abuse controls
- formal cryptographic review of the live production path

---

## Security posture

Qubee is being hardened toward the following properties:

- native cryptography as the only trusted production path
- hybrid session establishment for improved resistance against future quantum attacks
- ratcheting live message path for forward secrecy and state evolution
- replay protection and AAD-bound message metadata
- local secret protection through Android Keystore and encrypted app storage
- explicit trust reset and re-verification on peer key changes

### Important honesty clause

Qubee should **not** currently be described as a finished, formally trustworthy, fully post-quantum messenger.

The repository contains meaningful remediation work, but the project still needs real build verification, device testing, and full end-to-end confirmation that the live path always uses the intended native hybrid route.

---

## Repository layout

```text
Qubee/
├── app/
│   ├── src/main/appshell/             # Active Android source set
│   │   ├── java/com/qubee/messenger/
│   │   │   ├── crypto/                # Android crypto bridge and engine logic
│   │   │   ├── data/                  # Repository, Room, service locator
│   │   │   ├── model/                 # UI and app models
│   │   │   ├── network/p2p/           # WebRTC/bootstrap/transport plumbing
│   │   │   ├── permissions/           # Runtime permission handling
│   │   │   ├── security/              # Unlock, keystore, kill switch, DB passphrase
│   │   │   ├── service/               # Foreground/background node service
│   │   │   └── ui/                    # Compose screens, theme, navigation
│   │   └── res/
│   ├── build.gradle
│   └── proguard-rules.pro
├── docs/
│   ├── protocol/                      # Protocol contracts and object formats
│   ├── testing/                       # Alpha slice plans and validation notes
│   └── AUDIT_REMEDIATION_PASS*.md     # Security remediation notes
├── src/
│   ├── native_contract.rs             # Core native session/message path
│   ├── jni_api.rs                     # JNI bridge
│   ├── hybrid_ratchet.rs              # Ratchet-related native logic
│   ├── relay_protocol.rs              # Relay protocol messages
│   ├── relay_security.rs              # Relay TLS / rate limiting hardening
│   ├── security/                      # Secure keystore, memory, RNG
│   ├── crypto/                        # Crypto support modules
│   ├── testing/                       # Rust-side security tests
│   └── bin/qubee_relay_server.rs      # Reference relay server
├── Cargo.toml
├── build_rust.sh
├── build_rust.ps1
├── settings.gradle
└── rust-toolchain.toml
```

---

## Architecture overview

### Android layer

The Android application is responsible for:

- unlock and app lifecycle
- UI and navigation
- local persistence and observable state
- permission handling
- QR bootstrap UX
- connectivity diagnostics
- background work and recovery flows

### Native Rust layer

The Rust core is responsible for:

- sensitive cryptographic operations
- native session establishment
- message encryption / decryption
- ratchet-related state transitions
- replay / AAD enforcement on the native path
- relay authentication primitives

### Transport layer

Qubee currently works with a layered transport model:

- preferred live peer path: **WebRTC-oriented direct channel**
- bootstrap and recovery assistance: **relay and local bootstrap paths**
- diagnostics and fallback state exposed to the UI

The goal is not to confuse "encrypted tunnel exists somewhere" with "messaging protocol is finished." Transport and messaging semantics remain separate concerns.

---

## Build prerequisites

### Android

- Android Studio Hedgehog or newer is recommended
- Android SDK 34
- Java 17
- Android NDK if rebuilding the Rust shared library

### Rust

- stable Rust toolchain
- `cargo-ndk` for Android targets
- Android NDK toolchain installed and configured

---

## Building the Rust library

The Rust crate builds a shared library used by the Android app.

### Linux / macOS

```bash
./build_rust.sh
```

### Windows PowerShell

```powershell
./build_rust.ps1
```

The Android JNI libraries are copied into:

```text
app/src/main/jniLibs/
```

### Manual build example

```bash
cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release
cargo ndk -t armeabi-v7a -o app/src/main/jniLibs build --release
cargo ndk -t x86_64 -o app/src/main/jniLibs build --release
cargo ndk -t x86 -o app/src/main/jniLibs build --release
```

---

## Running the Android app

1. Open the repository in **Android Studio**
2. Let Gradle sync
3. Build the Rust JNI library into `app/src/main/jniLibs`
4. Run the `app` module on a device or emulator

Current debug builds use a default relay URL configured in `app/build.gradle`.

---

## Running the reference relay

The relay exists for protocol iteration, bootstrap, recovery, and controlled fallback.

### Start without TLS

```bash
cargo run --bin qubee_relay_server
```

### Environment variables

- `QUBEE_RELAY_BIND` — bind address, default: `0.0.0.0:8787`
- `QUBEE_RELAY_TLS_CERT_PATH` — optional TLS certificate path
- `QUBEE_RELAY_TLS_KEY_PATH` — optional TLS private key path

### Example with TLS

```bash
export QUBEE_RELAY_BIND=0.0.0.0:8787
export QUBEE_RELAY_TLS_CERT_PATH=/path/to/fullchain.pem
export QUBEE_RELAY_TLS_KEY_PATH=/path/to/privkey.pem
cargo run --bin qubee_relay_server
```

If both TLS variables are set, the relay serves `wss://`.

---

## Android dependencies of note

The Android module currently includes:

- Jetpack Compose / Material 3
- Room
- SQLCipher dependency seam
- WorkManager
- BiometricPrompt
- WebRTC
- ZXing

See `app/build.gradle` for the exact dependency list.

---

## Key project flows

### Unlock flow

The app is designed so that sensitive repository/database access happens **after unlock**, not before. The intended production posture is:

1. authenticate user
2. unlock keystore-backed material
3. open encrypted local storage
4. restore native-backed identity/session state
5. enter the application shell

### Contact bootstrap

1. export invite
2. scan / import peer invite
3. inspect peer bundle
4. compare safety code
5. verify trust
6. establish native session

### Messaging path

1. establish trusted native session
2. send encrypted message over the preferred live path
3. fall back for recovery or coordination when necessary
4. reconcile missed history after reconnect
5. invalidate trust on key change

---

## Protocol and design documentation

Start here if you want the real shape of the project instead of optimistic mythology:

### Core docs

- `docs/JNI_BRIDGE_CONTRACT.md`
- `docs/PROTOTYPE_TO_PRODUCTION_GAP.md`
- `docs/IMPLEMENTATION_STRATEGY_ALIGNMENT.md`
- `docs/ROADMAP_ALPHA.md`
- `docs/testing/ALPHA_VERTICAL_SLICE.md`

### Protocol docs

- `docs/protocol/native-api.md`
- `docs/protocol/identity-bundle.md`
- `docs/protocol/message-envelope.md`
- `docs/protocol/session-state.md`
- `docs/protocol/trust-state-machine.md`
- `docs/protocol/device-linking.md`

### Security remediation notes

- `docs/RUST_REMEDIATION_PASS_1.md`
- `docs/RUST_REMEDIATION_PASS_2.md`
- `docs/AUDIT_REMEDIATION_PASS3.md`
- `docs/AUDIT_REMEDIATION_PASS4.md`
- `docs/AUDIT_REMEDIATION_PASS5.md`
- `docs/AUDIT_REMEDIATION_PASS6.md`

---

## Testing status

The repository contains tests and validation notes, but you should assume the following until proven otherwise on your own machines:

- Android build/runtime has **not** been fully verified across real devices from this repository state
- Rust build/runtime has **not** been fully verified in every remediation pass
- the project still needs end-to-end validation for:
  - native hybrid session establishment
  - live ratcheting message flow
  - replay rejection
  - reconnect reconciliation
  - trust reset on key change
  - kill switch behavior

This repo is much more serious than a throwaway mockup, but it still requires real testing before any strong trust claims are justified.

---

## Known limitations

- preview/demo-era code still exists in parts of the history and must not be mistaken for trusted production crypto
- relay is still a reference implementation, not a finished hardened service deployment
- device testing is still required for BLE, Wi-Fi Direct, WebRTC lifecycle, and permission behavior
- the project is still in transition from “secure prototype” to “credible private alpha”

---

## Development priorities

If you are continuing work on Qubee, the next priorities are:

1. compile and test the current Rust + Android state together
2. confirm the native hybrid path is the only trusted production route
3. validate ratchet behavior on the live message path
4. finish relay hardening and deployment controls
5. quarantine or strip preview-only crypto from production builds
6. complete device-level validation for bootstrap, recovery, and permissions

---

## Philosophy

Qubee is trying to avoid a common trap in secure messaging projects:

> beautiful UI + serious cryptography words + a transport stack that quietly cheats.

The project is being pushed toward a much stricter model:

- the UI must tell the truth
- trust state must be explicit
- fallback paths must not pretend to be equally secure
- native cryptography must own the trusted path
- recovery and diagnostics must be operational, not decorative

That makes the app less magical, but much more honest.

---

## License

See `LICENSE.md`.
