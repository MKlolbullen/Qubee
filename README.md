# 🚀 Qubee is a cutting-edge, post-quantum secure, peer-to-peer messaging and file transfer application designed for maximum privacy and security — with no centralized servers.

File structure
```markdown
Qubee/
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── hybrid_ratchet.rs
│   ├── secure_message.rs      
│   ├── file_transfer.rs       
│   ├── audio.rs               
│   ├── identity.rs
│   ├── error.rs
│   ├── logging.rs
│   ├── config.rs
│   ├── ephemeral_keys.rs
│   ├── sas.rs
│   └── oob_secret.rs
│
├── Cargo.toml
└── README.md
```

---

🔒 Features

✅ Post-Quantum Security:

Hybrid Double Ratchet with Kyber-768 and Dilithium-2 ensures robust protection against future quantum attacks.


✅ Sealed Sender:

Ephemeral signatures on every packet, protecting sender metadata.


✅ Ephemeral Key Pinning:

Trust-on-first-use (TOFU) detection of ephemeral key changes to detect potential MITM attempts.


✅ Cover Traffic:

Dummy packets injected into audio, text, and file streams, preventing traffic analysis and metadata leakage.


✅ File Integrity Verification:

Per-file hash checking ensures every transferred file is complete and untampered.


✅ Zero-Knowledge Proof Interface (Pluggable):

Hooks for integrating zk-SNARKs/Bulletproofs in the future.


✅ No Backend Servers:

100% peer-to-peer, no cloud dependencies.


✅ Configurable Trust Model:

Choose between TOFU or pre-pinned keys.


✅ Modular Architecture:

Written in Rust for performance and safety.



---

📚 Installation
```sh
git clone https://github.com/yourusername/pq_messenger.git
cd pq_messenger
cargo build --release
```

---

🛠️ Usage

Run the application:
```sh
cargo run --release
```

---

⚙️ Configuration

Adjust runtime settings in src/config.rs:

pub struct AppConfig {
    pub enable_cover_traffic: bool,
    pub dummy_packet_frequency_secs: u64,
    pub trust_model: String, // \"TOFU\" or \"pinned\"
}


---

🧩 Modules

secure_message.rs: Text messaging with Sealed Sender.

file_transfer.rs: Chunked file transfer with ephemeral key pinning.

audio.rs: Real-time encrypted audio with dummy packet support.

hybrid_ratchet.rs: Combines classical Double Ratchet with PQ Kyber KEM.

identity.rs: Handles Dilithium-based identity key management.

ephemeral_keys.rs: TOFU ephemeral key store.

config.rs: App configuration.

logging.rs: Tracing integration.

error.rs: Structured error handling.

sas.rs: Short Authentication Strings (SAS) generator.

oob_secret.rs: Out-of-Band secret generator.



---

🧪 Benchmarking

Run with:
```
cargo run --release
```
Logs CPU times and encryption/decryption performance automatically.


---

🤝 Contributing

Contributions welcome! Please submit pull requests with detailed descriptions.


---

🛡️ License

MIT — see LICENSE file for details.


---

📞 Contact

Victor — 0daybullen@protonmail.com 

