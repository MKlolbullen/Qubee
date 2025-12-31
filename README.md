# Qubee

> **Post-quantum, peer-to-peer messaging, audio/video calls & file-sharing.**  
> Built with **Android (Kotlin + Compose)** and **Rust** for maximum security and performance.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.77%2B-orange)
![Status](https://img.shields.io/badge/status-experimental-red)

---

## 🔍 Overview

Qubee is a research-grade secure messenger that eliminates centralized infrastructure. It uses a **hybrid cryptographic scheme** combining classical algorithms (X25519) with post-quantum standards (Kyber-768, Dilithium-2) to ensure long-term confidentiality and authentication.

The core logic and cryptography are implemented in **Rust** for memory safety and performance, exposed to the **Android** application via JNI.

## ✨ Features

| Category | Qubee |
|----------|-------|
| **Post-quantum** | Kyber-768 KEM + Dilithium-2 signatures inside a Double Ratchet. |
| **P2P** | 100% peer-to-peer; metadata never touches a server. |
| **Sealed Sender** | Ephemeral Dilithium signatures per packet for sender unlinkability. |
| **Architecture** | Hybrid: Android (UI/Service) + Rust (Crypto/Protocol). |
| **Zero Servers** | NAT traversal via UDP hole-punching. |
| **Security** | Encrypted local storage (Room + SQLCipher), secure memory handling. |

## 🛠 Tech Stack

### Android (Client)
*   **Language:** Kotlin
*   **UI:** Jetpack Compose (Material3)
*   **Architecture:** MVVM, Hilt (DI), Coroutines/Flow
*   **Storage:** Room Database
*   **Networking:** Retrofit / OkHttp (for signaling/discovery)

### Rust (Core)
*   **Crate:** `qubee_crypto`
*   **Interface:** JNI (`jni` crate)
*   **Async Runtime:** Tokio
*   **Cryptography:** `pqcrypto-kyber`, `pqcrypto-dilithium`, `x25519-dalek`, `chacha20poly1305`, `blake3`.

## 🚀 Setup & Build

### Prerequisites
1.  **Android Studio** (Ladybug or newer recommended).
2.  **Rust Toolchain** (Stable).
3.  **Android NDK** (Installed via SDK Manager).
4.  **cargo-ndk**:
    ```bash
    cargo install cargo-ndk
    ```

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/Qubee.git
cd Qubee
```

### 2. Build Rust Core
You must compile the Rust shared libraries (`.so`) before building the Android app.

**Using the script (Linux/macOS/WSL):**
```bash
chmod +x build_rust.sh
./build_rust.sh
```

**Using PowerShell (Windows):**
```powershell
./build_rust.ps1
```

*This will compile the Rust code for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64` and place the libs in `app/src/main/jniLibs`.*

### 3. Run Android App
1.  Open `Qubee` project in Android Studio.
2.  Sync Gradle with project.
3.  Select a device/emulator and click **Run**.

## 📂 Project Structure

```text
Qubee/
├── app/                  # Android Application
│   ├── src/main/java/    # Kotlin source (UI, Services, DB)
│   ├── src/main/jniLibs/ # Compiled Rust libraries (.so)
│   └── build.gradle      # App-level build config
├── src/                  # Rust Core Source (`qubee_crypto`)
│   ├── crypto/           # Ratchet & Protocol logic
│   ├── security/         # Secure memory & RNG
│   ├── jni_api.rs        # JNI Bridge
│   └── lib.rs            # Entry point
├── Cargo.toml            # Rust dependencies
├── build_rust.sh         # Build script (Bash)
└── build_rust.ps1        # Build script (PowerShell)
```

## 🔐 Security Architecture

Qubee implements a **Defense in Depth** model:

*   **Memory Security:** `secure_memory.rs` handles sensitive data with locking and zeroization.
*   **Storage Security:** Keys are stored encrypted using platform-specific keystores (Android Keystore + SQLCipher).
*   **Audit:** Built-in security audit framework (`security_auditor.rs`) to check for runtime vulnerabilities.

## ✅ Tests

### Rust Tests
Run core logic tests:
```bash
cargo test
```

### Android Tests
Run UI and Integration tests via Gradle:
```bash
./gradlew test connectedAndroidTest
```

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Disclaimer: Qubee is research-grade software. Do not use for critical safety-of-life communications.*
