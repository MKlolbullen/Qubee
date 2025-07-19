# Qubee  <!-- Logo/branding here later -->
> **Post-quantum, peer-to-peer messaging & file-sharing—no servers, no excuses.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.77%2B-orange)
![Status](https://img.shields.io/badge/status-experimental-red)

## Table of Contents
1. [Why Qubee?](#why-qubee)
2. [Features](#features)
3. [Quick Start](#quick-start)
4. [Architecture](#architecture)
5. [Security Model](#security-model)
6. [Configuration](#configuration)
7. [Roadmap](#roadmap)
8. [Benchmarks](#benchmarks)
9. [Contributing](#contributing)
10. [License](#license)

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

## Quick Start

```bash
git clone https://github.com/MKlolbullen/Qubee.git
cd Qubee
cargo build --release
./target/release/qubee --help