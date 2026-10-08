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
//! Calling is host-tested under `--features calling`, but it is still
//! not a shipped capability: the default native library is built without
//! the feature, video capture is not implemented, and the physical-device
//! matrix in issue #79 is unrecorded. See
//! `docs/architecture/calling-threat-model.md` for the media-security
//! boundary and the ICE metadata leak.

pub mod call_manager;
pub mod media_encryption;
pub mod media_policy;
pub mod peer_connection;
pub mod realtime_queue;
pub mod signaling;
pub mod vp8_reassembly;
pub mod webrtc_manager;

pub use call_manager::{Call, CallManager, CallState, CallType};
pub use media_encryption::{MediaEncryption, MediaKey, StreamEncryption};
pub use peer_connection::{ICECandidate, PeerConnection, PeerConnectionState};
pub use signaling::{SignalingClient, SignalingMessage, SignalingServer};
pub use webrtc_manager::{WebRTCConfig, WebRTCManager};
