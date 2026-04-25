//! WebRTC-backed voice/video calling. **Feature-gated and unfinished.**
//!
//! Enable with `cargo build --features calling`. Without the flag, the
//! whole module is excluded from the crate so the rest of Qubee builds
//! clean.
//!
//! # Audit punch list (Round 7)
//!
//! Things that look right:
//!
//! * `media_encryption.rs` — small, self-contained ChaCha20-Poly1305
//!   over HKDF-derived per-stream keys. No external dep landmines, no
//!   placeholder branches; it's the closest piece to "ready".
//! * `signaling.rs` — pure-Rust message types and an in-memory router,
//!   no I/O. The wire types are reasonable. The `CallSignal`
//!   compatibility shim near the bottom of the file is consumed by no
//!   external caller today.
//!
//! Things that need real work before this module compiles, even with
//! the feature on:
//!
//! 1. **`peer_connection.rs` webrtc API paths target an older
//!    webrtc-rs.** We pin `webrtc = "0.14"` but the imports look like
//!    0.6/0.7: `webrtc::peer_connection::peer_connection::RTCPeerConnection`
//!    is doubled, `RTCSdpType` and friends moved, several methods
//!    have been renamed/relocated. This file needs a mechanical
//!    sweep against the 0.14 API.
//! 2. **`Cargo.toml` webrtc feature flags were fabricated.** The
//!    previous spec listed `["api", "peer-connection", "data", "media",
//!    "dtls", "ice", "sctp", "rtp", "rtcp", "sdp"]`; none of those
//!    are real features in webrtc 0.14, so dependency resolution
//!    failed before we ever reached compile errors. Now using default
//!    features — adjust if/when 0.14 grows real ones.
//! 3. **`webrtc_manager.rs` references `MediaDevicesManager`** as a
//!    field type but no such type is defined in the module today.
//!    Look for the missing struct definition and either add it or
//!    drop the field.
//! 4. **`call_manager.rs` is ~900 lines** of orchestration that lean
//!    on the broken peer_connection layer. It will start failing
//!    further as 1–3 are fixed; budget time for follow-on errors.
//!
//! Trivial bugs already fixed in Round 7:
//!
//! * Removed a JS-stub corruption line from `peer_connection.rs:8`
//!   (same artefact as the one previously found in
//!   `secure_keystore.rs`).
//! * Deduplicated `use std::sync::Arc;` in `call_manager.rs`.
//! * `webrtc_manager.rs` was importing `TurnServer` from
//!   `signaling`; the type lives in `call_manager`. Fixed.

pub mod call_manager;
pub mod media_encryption;
pub mod peer_connection;
pub mod signaling;
pub mod webrtc_manager;

pub use call_manager::{Call, CallManager, CallState, CallType};
pub use media_encryption::{MediaEncryption, MediaKey, StreamEncryption};
pub use peer_connection::{ICECandidate, PeerConnection, PeerConnectionState};
pub use signaling::{SignalingClient, SignalingMessage, SignalingServer};
pub use webrtc_manager::{WebRTCConfig, WebRTCManager};
