<p align="center">
  <img src="docs/branding/qubee_mark_master.svg" alt="Qubee" width="300" />
</p>

# Qubee

**An Android messenger exploring private conversations with less metadata.**

Qubee combines a Kotlin Android client with a Rust cryptographic and peer-to-peer
core. The goal is a functional, metadata-minimizing messenger inspired by
**Session, Threema, and Teleguard**—not a claim of equivalent features, anonymity,
or security.

> **Pre-alpha • For contributors and early testers • No independent security audit**
>
> A buildable Android app exists, with onboarding, contacts, chats, groups, and
> encrypted storage. Peer discovery and physical-device acceptance remain
> incomplete. Do not use Qubee for sensitive or safety-critical communications.

[Android setup](#build-the-android-app) · [Install](#install-and-try-it) ·
[Development](#local-development-and-tests) · [Security policy](SECURITY.md)

## What is implemented?

These are implementation capabilities, not a production-readiness checklist.

| Area | Current implementation and limits |
|---|---|
| Android client | Kotlin/Jetpack Compose onboarding, contact and chat screens, group management, and optional app lock. |
| Identity and verification | Rust-managed Ed25519 + ML-DSA-44 hybrid signatures; QR identity links, fingerprints, and short authentication string (SAS) comparison. A valid signature alone does not identify a person. |
| Default message sending | The existing shared-group-key compatibility envelope is used for both 1:1 and group conversations. **Ratchet sending defaults to off.** |
| Opt-in ratchet paths | PQXDH-style ML-KEM-768/X25519 establishment and persistent Double Ratchet for 1:1; sender-key chains and keyed-selector v5 frames for groups. Wired through JNI and the send orchestrator, but rollout awaits physical-device validation. |
| Delivery | Acknowledgement handling and durable ciphertext retries exist. They do not provide a hosted offline mailbox or guarantee reachability. |
| Attachments | Encrypted messages can carry files up to **256 KiB**. Local attachment copies use Android Keystore-backed encryption; large/chunked transfers are not implemented. |
| Storage | Room/SQLCipher for Android records; an encrypted Rust keystore for identities, group keys, and ratchet state. Upgrade and cross-store crash recovery need device testing. |
| Networking | libp2p TCP/Noise/Yamux and QUIC, gossipsub, Kademlia, and a direct request-response channel. **Android discovery/bootstrap wiring is incomplete; see below.** |
| Voice/video calls | Disabled by default; build-gated research integration with runtime privacy/provisioning gates. Not a usable default-app feature. |
| Voice messages, Tor/Nym transport, multi-device sync | Goals or unfinished work, not shipped capabilities. |

### Android compatibility and build status

- **Minimum:** Android 12L / API **32**. Android 12 / API 31 and older cannot install it.
- **Compile and target SDK:** Android 14 / API **34**. This is not an upper
  installation limit or a guarantee of compatibility with every newer Android version.
- **Native ABIs built:** `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`.
- The repository has APK build, JVM screenshot, Rust/JNI, and instrumented-test
  workflows. The instrumented workflow uses an **API 34 x86_64 emulator**.
  Successful builds and isolated tests are not proof of end-to-end phone delivery.
- Real-device lifecycle, network transitions, OEM background restrictions, and
  migrations remain acceptance work. The
  [Samsung Android 16 checklist](docs/manual-testing/samsung-android16-apk-acceptance.md)
  explicitly records **NOT RUN**.

### Connectivity is the main early-testing caveat

`P2PNodeConfig` disables mDNS by default. Android starts the default node, and
`nativeStartNetwork` currently reads but **does not use** its bootstrap-node
argument. There is no user-facing peer-address/bootstrap configuration.
Simply installing Qubee on two phones on the same Wi-Fi does **not** establish a
working peer mesh. Kademlia also needs known peers to get started.

Host P2P tests explicitly dial known loopback addresses; the stock Android flow
does not expose that test setup. Onboarding and local UI can be explored now,
but two-device messaging requires contributor work on discovery/routing first.
The [two-device walkthrough](docs/two-device-walkthrough.md) is useful background,
but its automatic mDNS discovery and some protocol descriptions are historical,
not current setup guarantees.

## Privacy and security: intent versus guarantees

Reducing metadata is a design priority, **not a solved property**. Anonymous
gossipsub authorship, rotating blinded topics, and keyed selectors reduce
specific disclosures. Padding is implemented on the ratchet paths; it should
not be assumed for every compatibility frame.

Direct peers can still see IP addresses. Network observers can correlate
timing, presence, and traffic volume; Kademlia address propagation and known
identity selectors can reveal more. There is no deployed onion/mixnet transport,
cover traffic, or traffic-analysis resistance. See the
[network privacy analysis](docs/architecture/network-privacy.md).

Rust is the cryptographic authority; Kotlin orchestrates UI, permissions,
services, and storage. Payload encryption uses ChaCha20-Poly1305, and hybrid
identity verification requires both signature components. The opt-in direct
ratchet's initial PQ exchange targets harvest-now/decrypt-later resistance;
subsequent DH ratcheting is classical. This is not recurring PQ ratcheting,
quantum post-compromise security, MLS, or FIPS validation. Do not attribute
ratchet guarantees to the default compatibility send path.

Other important boundaries:

- The prekey implementation has a single one-time prekey, not an ID-addressed
  pool; concurrent initiators can encounter an already-consumed key.
- Rust-store transactions do not atomically cover Room, JNI callbacks, and
  network transmission. Restoring old protocol snapshots can reuse keys.
- Android backups are disabled. Old plaintext-index Rust stores migrate on
  open; older binaries cannot read the new encrypted snapshot. Downgrading does
  not reverse migration, and Room retains a destructive migration fallback.
- Opening an attachment exports plaintext to an external viewer. Temporary
  exports expire while the app runs or are purged at next startup; the viewer
  may retain a copy. A compromised, unlocked endpoint can read plaintext.

Read the [crypto-boundary review](docs/security/crypto-boundary-hardening.md),
[key-persistence review](docs/security/key-persistence-hardening.md), and
[security policy](SECURITY.md) before testing trust or recovery behavior.

## Architecture

```text
Android UI (Kotlin / Jetpack Compose)
    ├── Hilt, Room / SQLCipher, Android Keystore
    └── QubeeManager / MessageService
                  │ JNI
Rust core (qubee_crypto)
    ├── Identity, onboarding, groups, ratchets, encrypted keystore
    └── Tokio / libp2p → TCP + QUIC peer connections
```

| Location | Purpose |
|---|---|
| [`app/`](app/) | Android application, resources, JVM and instrumented tests |
| [`src/`](src/) | Rust protocol, cryptography, networking, persistence, and JNI exports |
| [`tests/`](tests/) | Host integration tests, P2P tests, and pinned wire-format vectors |
| [`scripts/`](scripts/) | JNI contract checks and development/audit utilities |
| [`docs/architecture/`](docs/architecture/) | Protocol and threat-model details |

## Build the Android app

The following Bash setup targets **Linux**, matching the Android build workflows.
Use Android Studio's SDK Manager or the Android command-line tools to install
the SDK components. Android Studio is convenient, but not required.

### 1. Install prerequisites

| Tool | Required setup |
|---|---|
| Git | Clone the source repository |
| JDK | **17**; point `JAVA_HOME` and Android Studio's Gradle JDK at it |
| Android SDK | Command-line Tools (latest), Platform-Tools (`adb`), platform **34**, Build-Tools **34.0.0** |
| Android NDK | **26.1.10909125 / r26b**, installed side by side |
| Rust via rustup | Repository pins **1.88.0**, with rustfmt and Clippy |
| Native host tools | C/C++ compiler and linker for native dependencies; e.g. Ubuntu's `build-essential` |
| cargo-ndk | **3.x**; installed below |

Gradle **8.7** is supplied by the committed wrapper; do not install a separate
Gradle version. Initial builds download Cargo and Maven dependencies and need
internet access, disk space, and sufficient RAM (the Gradle daemon uses a 4 GiB heap).

### 2. Clone and configure the SDK

```bash
git clone https://github.com/MKlolbullen/Qubee.git
cd Qubee

# Change this if SDK Manager shows a different SDK location.
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/26.1.10909125"
export NDK_HOME="$ANDROID_NDK_HOME"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0" "ndk;26.1.10909125"

java -version
rustup show
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk --locked --version '^3'
```

Accept the Android SDK licenses when prompted. `java -version` should report 17;
`rustup show` from the repository selects its pinned toolchain.
Gradle can use `ANDROID_HOME`, or an uncommitted `local.properties` with an
absolute `sdk.dir` path. No release-signing credentials are needed for debug builds.

### 3. Build native libraries, then the APK

```bash
./build_rust.sh
./gradlew :app:assembleDebug
```

**Gradle does not build Rust automatically.** Re-run the native step after Rust
or JNI changes. It writes `libqubee_crypto.so` into
`app/src/main/jniLibs/<abi>/`; the debug APK is
`app/build/outputs/apk/debug/app-debug.apk`. Neither output belongs in commits.
In Android Studio, open the repository root and build/run `app` only after the
native libraries exist.

**Other development hosts:** `build_rust.ps1` and `gradlew.bat` exist for Windows.
After installing the same prerequisites and Rust targets, PowerShell can use:

```powershell
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:ANDROID_NDK_HOME = "$env:ANDROID_HOME\ndk\26.1.10909125"
$env:NDK_HOME = $env:ANDROID_NDK_HOME
cargo install cargo-ndk --locked --version '^3'
.\build_rust.ps1
.\gradlew.bat :app:assembleDebug
```

The PowerShell script is not identical to the Linux script's locked/path-remapped
build. Linux is the CI reference. On macOS, `build_rust.sh` uses GNU
`find -printf`/`sort -z`, which the default BSD tools do not support; use GNU
tools or invoke its `cargo ndk ... build --release --locked` commands directly.
These host alternatives are not additional shipped client platforms.

## Install and try it

### Physical Android device

Use a disposable test installation on **API 32 or newer**. Enable Developer
options and USB debugging, connect the device, and authorize the computer:

```bash
adb devices
./gradlew :app:installDebug
adb shell am start -n com.qubee.messenger/.ui.main.MainActivity
```

Alternatively, install the built APK directly:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

With multiple devices, use `adb -s SERIAL install -r ...` with the APK path above.
Launch Qubee, choose a display name, generate an identity, and explore contacts,
QR links, groups, and settings. Grant camera permission for QR scanning and
notification permission when requested. Use synthetic messages and disposable
identities; the [connectivity caveat](#connectivity-is-the-main-early-testing-caveat)
applies before attempting a peer exchange.

### Android emulator

In Android Studio's Device Manager, create and start an **API 34** virtual
device. CI uses a Google APIs **x86_64** image; use an image compatible with your
host and one of the built ABIs. Then use the same `adb`/`installDebug` commands.
An emulator permits UI and instrumented testing, not a substitute for two-phone,
Doze, or OEM acceptance testing.

### Workflow artifacts and signing

The [Android Build Smoke workflow](.github/workflows/android-smoke.yml) uploads
test APKs after a successful build. Maintainers can also dispatch
[Build APK (on demand)](.github/workflows/apk.yml). Download the artifact from a
successful run for the exact revision under test, unzip it, and check its
`SHA256SUMS`. Artifacts expire; workflow existence is not a promise that a
download is currently available.

These are test builds, including debug-signed, R8-minified release variants—not
production releases. Local `assembleRelease` also falls back to debug signing
without a configured keystore. The tagged release workflow requires real signing
secrets; see [release instructions](RELEASE.md). This README does not assume a
current public release APK or app-store listing exists.

## Local development and tests

Run from the repository root. Host Rust checks do not require the Android SDK:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --features _typecheck_jni
cargo bench --locked --no-run
bash scripts/check_jni_contracts.sh
bash scripts/audit_message_file_bridge.sh
```

Android checks (SDK required; build native libraries first for app/device tests):

```bash
./gradlew :app:compileDebugKotlin :app:testDebugUnitTest
./gradlew :app:lintDebug
./gradlew :app:verifyPaparazziDebug
# Requires a connected API 32+ device or running emulator:
./gradlew :app:connectedDebugAndroidTest
```

Paparazzi renders stateless Compose screens on the JVM without a device or JNI.
See [screenshot testing](docs/screenshot-tests.md) for intentional baseline updates.
Do not regenerate baselines just to hide an unexpected failure.

### Configuration and experimental paths

- `PreferenceRepository.ratchetSendEnabled()` defaults to `false`;
  `RatchetSender` selects the opt-in direct/sender-key send paths. There is
  currently **no Settings toggle** for this preference; opting in requires
  developer wiring through `setRatchetSendEnabled`. Receive-side support exists
  independently. Opt-in encryption failures do not fall back to compatibility
  sending.
- Keep default Cargo features for normal development. The `legacy` feature
  exposes unported prototype modules; avoid `--all-features`, including the
  doctor script's all-feature Clippy step, as a default-build health check.
- Calling research requires **both** build opt-ins:
  ```bash
  QUBEE_CALLING=1 ./build_rust.sh
  ./gradlew :app:assembleDebug -PqubeeCalling=true
  ```
  This does not remove the runtime gate requiring TURN/private signaling
  provisioning or establish device readiness. Current media protection is
  WebRTC DTLS-SRTP, not the separate in-tree frame-encryption helper. Consult the
  [calling threat model](docs/architecture/calling-threat-model.md) and
  [deployment notes](deploy/calling/README.md).

## Troubleshooting

| Symptom | What to check |
|---|---|
| SDK location not found | Set `ANDROID_HOME` to the real SDK directory or set `sdk.dir` in local `local.properties`; accept SDK licenses. |
| Gradle JDK/plugin error | Use JDK 17 and the committed wrapper, including Android Studio's Gradle JDK setting. |
| `cargo ndk` missing / compiler missing | Install cargo-ndk 3.x, all four Rust targets, and NDK r26b; check `ANDROID_NDK_HOME` is the NDK directory, not the SDK root. |
| Native library/JNI linkage failure | Rebuild Rust before Gradle; check `app/src/main/jniLibs/<device-abi>/libqubee_crypto.so` and run both JNI contract scripts. |
| Device absent or unauthorized | Check `adb devices`, unlock the device, accept the USB-debugging prompt, and verify API/ABI compatibility. |
| APK signature mismatch or version downgrade | Existing debug/release installs may have different certificates or version codes. **Uninstalling or clearing data destroys local identities and messages**; use a disposable device/profile instead of casually resetting a valuable install. |
| No peer discovery / messages stay pending | Same Wi-Fi and exchanging QR links are not enough with current discovery wiring. Do not treat `SENT` or a queued publish as remote delivery. Check routing and prekey/group membership before blaming encryption. |
| Screenshot mismatch | Inspect `app/build/paparazzi/failures/` and compare against committed snapshots. |

For build diagnostics, append `--stacktrace` to Gradle commands. Before sharing
logs, remove identifiers, IP addresses, message content, and any key material.
Some older docs, especially [build-status.md](docs/build-status.md), are historical
snapshots; use current manifests, source, and workflow results rather than their
old test counts or shipping claims.

## Roadmap and contributions

Priorities are reliable Android peer discovery and routing, recorded multi-phone
acceptance, ratchet rollout and compatibility retirement, prekey pooling/rotation,
and cross-store crash recovery. Further metadata reduction, large attachments,
stored voice messages, private calling, and multi-device support remain future
work—not promises of a delivery date.

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Keep changes focused, add regression
tests for behavior changes, preserve wire-format vectors, and update both sides
of JNI together. Discuss new features and cryptographic changes before implementation.
Use the [device matrix](docs/manual-testing/ratchet-cutover-device-matrix.md) to
record actual results, not assumed passes.

Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
not in public issues.

## License

Qubee is licensed under the [MIT License](LICENSE.md).
