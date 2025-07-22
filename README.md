# Qubee  <!-- Logo/branding here later -->
> **Post-quantum, peer-to-peer messaging & file-sharing—no servers, no excuses.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.77%2B-orange)
![Status](https://img.shields.io/badge/status-experimental-red)
```markdown
QubeeSecureApp/
├── app/
│   ├── build.gradle
│   ├── proguard-rules.pro
│   ├── src/
│   │   └── main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/
│   │       │   └── com/
│   │       │       └── qubee/
│   │       │           └── secure/
│   │       │               ├── MainActivity.kt
│   │       │               ├── NativeLib.kt
│   │       │               └── KeyStoreHelper.kt
│   │       ├── cpp/
│   │       │   ├── Android.mk
│   │       │   └── Application.mk
│   │       └── jniLibs/
│   │           └── arm64-v8a/
│   │               └── libqubee.so  <-- built via cargo-ndk or ndk-build
├── qubee-crypto/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               <-- JNI entry point
│       ├── crypto/
│       │   └── identity.rs      <-- SecureSession, IdentityManager
├── build.gradle
├── settings.gradle
└── gradle.properties


```
## Table of Contents
1. [Why Qubee?](#why-qubee)
2. [Security Show-down](#SecurityShow-down)
3. [Features](#features)
4. [Quick Start](#quick-start)
5. [Architecture](#architecture)
6. [Security Model](#security-model)
6. [Configuration](#configuration)
8. [Roadmap](#roadmap)
9. [Benchmarks](#benchmarks)
10. [Contributing](#contributing)
11. [License](#license)

---

## Why Qubee?
Current “secure” messengers still hinge on **centralised infrastructure** or **pre-quantum key exchange**.  
Qubee flips the table:

* **100 % peer-to-peer**—metadata never touches a server.  
* **Hybrid Kyber-768 + Dilithium-2 Double Ratchet**—post-quantum confidentiality _and_ authentication.  
* **Rust first**—memory-safety without a garbage collector.

> **Reality check:** Qubee is *research-grade*. Expect sharp edges and zero backwards-compat guarantees.

## Features
| Category | Qubee |
|----------|-------|
| Post-quantum | Kyber-768 KEM + Dilithium-2 sigs inside a classical Double Ratchet. |
| Sealed Sender | Ephemeral Dilithium sig per packet—sender unlinkability. |
| Cover Traffic | Configurable dummy packets for audio, text & files. |
| File integrity | BLAKE3 chunk hashing; pass/fail before file release. |
| Trust model | TOFU _or_ pre-pinned keys; change alerts. |
| Zero servers | NAT traversal via UDP hole-punching; no fallback relay. |
| Extensible | Pluggable ZK-proof layer (SNARKs/Bulletproofs stubs). |

---

## Security Show-down: Qubee vs Signal (July 2025 snapshot)


| Axis | Qubee | Signal |
|------|-------|--------|
| **Cryptography** | Custom hybrid: X25519 + Kyber-768 (KEM) inside Double Ratchet; Dilithium-2 for identity/packet sigs. | Standard X3DH / PQXDH handshake and Double Ratchet; Ed25519 for identity keys. |
| **Post-quantum scope** | End-to-end (initial handshake **and** every ratchet step). | Handshake only (PQXDH); message ratchet still classical. 6 |
| **Metadata exposure** | None by design—no servers. NAT traversal leaks only to peers. | Relay servers log IP/timing (claimed to drop metadata but still single point). 7 |
| **Deniability** | Weak: Dilithium signatures provably bind messages to sender. | Strong cryptographic deniability; no long-term sigs. 8 |
| **Traffic analysis** | Dummy cover traffic on all channels. | None (relies on TLS). |
| **Implementation rigor** | Two commits, zero test coverage, no audit—**high risk**. 9 | Mature open-source, multiple formal/security reviews. 10 |
| **Usability** | CLI only; requires port-forwarding/hole-punch. | Polished mobile/desktop apps, push notifications. |
| **Dependency risk** | Pure Rust, no TLS, minimal deps. | Relies on Firebase/APNs for push (mobile). |
| **Risk summary** | Cutting-edge but unvetted; excellent lab demo, dangerous production bet. | Battle-tested; good enough for journalists and dissidents today. |

> **Hard truth:** Unless you personally audit & maintain Qubee, stick with Signal for real-life ops. Use Qubee as a playground for PQ crypto research—nothing more, nothing less.

---

## Quick Start

```bash
git clone https://github.com/MKlolbullen/Qubee.git
cd Qubee
cargo build --release
./target/release/qubee --help

---

## Security Show-down: Qubee vs Signal (July 2025 snapshot)



Enjoy, and feel free to fork the README further.
