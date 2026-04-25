//! WebRTC-backed voice/video calling. **Feature-gated and unfinished.**
//!
//! Enable with `cargo build --features calling`. Without the flag, the
//! whole module is excluded from the crate so the rest of Qubee builds
//! clean.
//!
//! # Audit log
//!
//! ## Already addressed
//!
//! Round 7 (build-hygiene cleanup):
//!
//! * Removed a JS-stub corruption line from `peer_connection.rs:8`
//!   (same artefact as the one previously found in
//!   `secure_keystore.rs`).
//! * Deduplicated `use std::sync::Arc;` in `call_manager.rs`.
//! * `webrtc_manager.rs` was importing `TurnServer` from
//!   `signaling`; the type lives in `call_manager`. Fixed.
//! * `Cargo.toml` previously claimed feature flags
//!   `["api","peer-connection","data","media","dtls","ice","sctp","rtp",
//!   "rtcp","sdp"]` — none of those are real features in webrtc 0.14,
//!   so resolution failed before we ever reached the type-checker.
//!   Switched to optional + default features.
//!
//! Round 8c (API-path sweep against webrtc 0.14):
//!
//! * `peer_connection::peer_connection::RTCPeerConnection` was a real
//!   doubled path — swapped to `peer_connection::RTCPeerConnection`.
//! * `RTCSdpType` moved out of `session_description` into a sibling
//!   `sdp_type` module — import updated.
//! * The `media::` namespace was flattened — track types now live
//!   directly under `webrtc::track::`. Imports updated.
//! * `RTCSessionDescription` no longer accepts struct-literal
//!   construction — replaced two call sites with the typed
//!   `RTCSessionDescription::offer(...)` / `::answer(...)` builders.
//!
//! ## Still outstanding
//!
//! 1. **Unverified at compile time.** Round 8c was edits-by-reading
//!    against a known webrtc 0.14 API; nothing was actually checked
//!    with `cargo check --features calling` because the sandbox has no
//!    cargo. There are likely a handful of follow-on type/signature
//!    mismatches (the `add_track` trait-object bound, codec-capability
//!    field reshuffling) that only show up when you run the build.
//! 2. **`call_manager.rs` is ~900 lines** of orchestration leaning on
//!    `peer_connection`'s newly-updated surface. Treat the first
//!    `--features calling` build as a starting point, not the end of
//!    the audit.
//! 3. **The `CallSignal` compatibility shim** at the bottom of
//!    `signaling.rs` has no callers. If it stays unused, drop it; if
//!    you intended to revive it for the message pipeline, write the
//!    test that drives it before bringing it back.
//!
//! ## Things that look right
//!
//! * `media_encryption.rs` — small, self-contained ChaCha20-Poly1305
//!   over HKDF-derived per-stream keys. The closest piece to "ready"
//!   in this module.
//! * `signaling.rs` — pure-Rust message types and an in-memory router,
//!   no I/O. The wire types are reasonable.
//! * `MediaDevicesManager` — earlier audit notes claimed this type was
//!   missing; it actually lives at `webrtc_manager.rs:38`. False alarm.

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
