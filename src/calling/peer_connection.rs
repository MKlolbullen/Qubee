use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::calling::call_manager::CallId;
use crate::calling::media_encryption::MediaKey;
use crate::calling::webrtc_manager::MediaStats;
use crate::calling::webrtc_manager::WebRTCConfig;
use crate::identity::identity_key::IdentityId;

// Imports updated for webrtc 0.14:
//   * `peer_connection::peer_connection::RTCPeerConnection` was
//     deduplicated to `peer_connection::RTCPeerConnection`.
//   * `RTCSdpType` moved out of `session_description` into its own
//     `sdp_type` module.
//   * The `media::` namespace was flattened — track types now live
//     directly under `webrtc::track::`.
use std::sync::Arc;
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::rtp_transceiver::rtp_sender::RTCRtpSender;
use webrtc::stats::StatsReportType;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use tokio::sync::Mutex;

/// Represents the state of a peer connection. Mirrors the variants
/// exposed by webrtc-rs's `RTCPeerConnectionState` so `state()` can
/// translate without information loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerConnectionState {
    /// Connection has been created but no offer/answer exchange has
    /// occurred yet.
    New,
    /// Offer/answer exchange has started.
    Connecting,
    /// Media and data channels are flowing.
    Connected,
    /// At least one transport has been disconnected. May recover
    /// without renegotiation.
    Disconnected,
    /// Connection has been gracefully closed.
    Closed,
    /// Connection failed due to negotiation or transport errors.
    Failed,
}

impl From<RTCPeerConnectionState> for PeerConnectionState {
    fn from(s: RTCPeerConnectionState) -> Self {
        match s {
            RTCPeerConnectionState::New | RTCPeerConnectionState::Unspecified => {
                PeerConnectionState::New
            }
            RTCPeerConnectionState::Connecting => PeerConnectionState::Connecting,
            RTCPeerConnectionState::Connected => PeerConnectionState::Connected,
            RTCPeerConnectionState::Disconnected => PeerConnectionState::Disconnected,
            RTCPeerConnectionState::Closed => PeerConnectionState::Closed,
            RTCPeerConnectionState::Failed => PeerConnectionState::Failed,
        }
    }
}

/// ICE candidate information used during WebRTC negotiation. These
/// correspond to the candidate fields in the SDP specification.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ICECandidate {
    /// Media identification string as used in SDP.
    pub sdp_mid: String,
    /// Media line index within the SDP description.
    pub sdp_mline_index: u32,
    /// The raw ICE candidate line.
    pub candidate: String,
}

/// Wraps a `webrtc::RTCPeerConnection` and exposes the slice of its
/// API the rest of the Qubee call stack uses: SDP offer/answer,
/// remote-candidate ingestion, audio/video track toggling, and
/// stats. The underlying crate handles ICE, DTLS, SRTP and SCTP.
///
/// `set_bandwidth_limit`, `set_noise_suppression` and
/// `set_echo_cancellation` are accepted but not enforced — the
/// former needs sender-parameter mutation that webrtc-rs 0.14
/// doesn't expose, and the latter two belong in the audio capture
/// pipeline (which lives outside this crate).
pub struct PeerConnection {
    /// Identifier of the call this peer connection belongs to.
    pub call_id: CallId,
    /// Identity of the remote participant.
    pub participant: IdentityId,
    /// Media encryption key used for SRTP/SRTCP once established.
    pub media_key: MediaKey,
    /// Current signalling and media state of the connection.
    pub(crate) state: PeerConnectionState,
    /// Underlying WebRTC peer connection. This is the main handle
    /// provided by the webrtc-rs crate and manages ICE, DTLS, SRTP and
    /// SCTP transports. We wrap it in an `Arc` so it can be cloned to
    /// attach event handlers if needed.
    webrtc_pc: Arc<RTCPeerConnection>,

    /// Optional audio track and sender. Wrapped in a mutex to allow
    /// mutation through an immutable reference to the peer connection.
    audio_track: Arc<Mutex<Option<Arc<TrackLocalStaticSample>>>>,
    audio_sender: Arc<Mutex<Option<Arc<RTCRtpSender>>>>,

    /// Optional video track and sender. As with audio, these are
    /// protected by mutexes so that toggling video is thread safe.
    video_track: Arc<Mutex<Option<Arc<TrackLocalStaticSample>>>>,
    video_sender: Arc<Mutex<Option<Arc<RTCRtpSender>>>>,
}

impl PeerConnection {
    /// Build a peer connection: translate Qubee's `WebRTCConfig` into
    /// the lower-level `RTCConfiguration`, fold each STUN/TURN entry
    /// into an `RTCIceServer`, and ask the webrtc-rs API for a fresh
    /// `RTCPeerConnection`. ICE gathering and DTLS setup happen lazily
    /// once a local description is installed via `create_offer` /
    /// `create_answer`.
    pub async fn new(
        config: WebRTCConfig,
        media_key: MediaKey,
        call_id: CallId,
        participant: IdentityId,
    ) -> Result<Self> {
        // Convert CallManager's WebRTCConfig into the lower-level RTCConfiguration
        // used by webrtc-rs. Each STUN/TURN server becomes an RTCIceServer.
        let mut ice_servers: Vec<RTCIceServer> = Vec::new();
        for url in config.stun_servers.iter() {
            ice_servers.push(RTCIceServer {
                urls: vec![url.clone()],
                ..Default::default()
            });
        }
        // Handle TURN servers if provided. The TurnServer struct has url,
        // username and credential fields which map directly to RTCIceServer.
        for turn in config.turn_servers.iter() {
            ice_servers.push(RTCIceServer {
                urls: vec![turn.url.clone()],
                username: turn.username.clone(),
                credential: turn.credential.clone(),
                ..Default::default()
            });
        }
        let rtc_config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };
        // Build the WebRTC API and create a new peer connection. The API
        // builder allows customising the media engine and interceptor
        // registry; for now we stick with defaults. If SRTP/DTLS is
        // disabled in the config, we could disable corresponding
        // interceptors here.
        let api = APIBuilder::new().build();
        let pc = api.new_peer_connection(rtc_config).await
            .context("Failed to create WebRTC peer connection")?;
        Ok(PeerConnection {
            call_id,
            participant,
            media_key,
            state: PeerConnectionState::New,
            webrtc_pc: Arc::new(pc),
            audio_track: Arc::new(Mutex::new(None)),
            audio_sender: Arc::new(Mutex::new(None)),
            video_track: Arc::new(Mutex::new(None)),
            video_sender: Arc::new(Mutex::new(None)),
        })
    }

    /// Live signalling/transport state pulled from webrtc-rs. Prefer
    /// this over the cached `state` field — the field only flips on
    /// `close()`, while this reflects ICE/DTLS health as the
    /// connection negotiates and recovers.
    pub fn state(&self) -> PeerConnectionState {
        self.webrtc_pc.connection_state().into()
    }

    /// Gracefully close the peer connection. Tears down ICE/DTLS/SRTP
    /// transports via the underlying webrtc-rs handle and flips the
    /// cached state to `Closed` so callers reading the field directly
    /// see the terminal value without an extra round-trip.
    pub async fn close(&mut self) -> Result<()> {
        self.webrtc_pc.close().await
            .context("Failed to close peer connection")?;
        self.state = PeerConnectionState::Closed;
        Ok(())
    }

    /// Enable or disable audio for this connection. When enabled, a
    /// local audio track is created (if none exists) and added to
    /// the underlying peer connection. When disabled, the existing
    /// track is removed by replacing it with `None` on the RTP
    /// sender. This method is idempotent.
    pub async fn set_audio_enabled(&self, enabled: bool) -> Result<()> {
        // Acquire locks on the track and sender. The scope of
        // the locks is limited to avoid holding them across awaits.
        let mut sender_opt = self.audio_sender.lock().await;
        let mut track_opt = self.audio_track.lock().await;

        if enabled {
            // If no sender exists yet, we need to create a new track
            // and add it to the peer connection. This will start
            // sending silence until samples are provided by the
            // application. For now we rely on the media subsystem to
            // handle silence frames.
            if sender_opt.is_none() {
                // Define the codec capability for Opus audio. We use
                // stereo at 48 kHz, which is widely supported.
                let audio_cap = RTCRtpCodecCapability {
                    mime_type: "audio/opus".to_string(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                };
                let track = Arc::new(TrackLocalStaticSample::new(
                    audio_cap.clone(),
                    "audio".to_string(),
                    "qubee-audio".to_string(),
                ));
                // Cast the track into a trait object. The add_track
                // function expects an Arc<dyn TrackLocal + Send + Sync>.
                let dyn_track: Arc<dyn TrackLocal + Send + Sync> = track.clone();
                let sender = self.webrtc_pc.add_track(dyn_track).await
                    .context("Failed to add audio track to peer connection")?;
                *track_opt = Some(track);
                *sender_opt = Some(sender);
            } else {
                // A sender already exists but may have been
                // previously disabled. Re-enable it by swapping
                // back in the track. If a track is missing, create
                // one as above.
                let track = if let Some(track) = track_opt.as_ref() {
                    track.clone()
                } else {
                    let audio_cap = RTCRtpCodecCapability {
                        mime_type: "audio/opus".to_string(),
                        clock_rate: 48000,
                        channels: 2,
                        sdp_fmtp_line: String::new(),
                        rtcp_feedback: vec![],
                    };
                    let t = Arc::new(TrackLocalStaticSample::new(
                        audio_cap,
                        "audio".to_string(),
                        "qubee-audio".to_string(),
                    ));
                    *track_opt = Some(t.clone());
                    t
                };
                if let Some(sender) = sender_opt.as_ref() {
                    // Replace the track on the sender. Some WebRTC
                    // implementations require `Some` to re-add.
                    let dyn_track: Arc<dyn TrackLocal + Send + Sync> = track.clone();
                    sender.replace_track(Some(dyn_track)).await
                        .context("Failed to enable audio track")?;
                }
            }
        } else {
            // Disable audio by replacing the track on the RTP sender
            // with None. This will cause silence on the remote end.
            if let Some(sender) = sender_opt.as_ref() {
                sender.replace_track(None).await
                    .context("Failed to disable audio track")?;
            }
        }
        Ok(())
    }

    /// Enable or disable video for this connection. When enabled, a
    /// local video track is created (if none exists) and added to
    /// the underlying peer connection. When disabled, the existing
    /// track is removed by replacing it with `None` on the RTP
    /// sender.
    pub async fn set_video_enabled(&self, enabled: bool) -> Result<()> {
        let mut sender_opt = self.video_sender.lock().await;
        let mut track_opt = self.video_track.lock().await;
        if enabled {
            if sender_opt.is_none() {
                // Use VP8 as the default video codec. Many browsers
                // and clients support VP8 without requiring H.264.
                let video_cap = RTCRtpCodecCapability {
                    mime_type: "video/VP8".to_string(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                };
                let track = Arc::new(TrackLocalStaticSample::new(
                    video_cap.clone(),
                    "video".to_string(),
                    "qubee-video".to_string(),
                ));
                let dyn_track: Arc<dyn TrackLocal + Send + Sync> = track.clone();
                let sender = self.webrtc_pc.add_track(dyn_track).await
                    .context("Failed to add video track to peer connection")?;
                *track_opt = Some(track);
                *sender_opt = Some(sender);
            } else {
                let track = if let Some(track) = track_opt.as_ref() {
                    track.clone()
                } else {
                    let video_cap = RTCRtpCodecCapability {
                        mime_type: "video/VP8".to_string(),
                        clock_rate: 90000,
                        channels: 0,
                        sdp_fmtp_line: String::new(),
                        rtcp_feedback: vec![],
                    };
                    let t = Arc::new(TrackLocalStaticSample::new(
                        video_cap,
                        "video".to_string(),
                        "qubee-video".to_string(),
                    ));
                    *track_opt = Some(t.clone());
                    t
                };
                if let Some(sender) = sender_opt.as_ref() {
                    let dyn_track: Arc<dyn TrackLocal + Send + Sync> = track.clone();
                    sender.replace_track(Some(dyn_track)).await
                        .context("Failed to enable video track")?;
                }
            }
        } else {
            if let Some(sender) = sender_opt.as_ref() {
                sender.replace_track(None).await
                    .context("Failed to disable video track")?;
            }
        }
        Ok(())
    }

    /// Begin screen capture on this peer connection. In this simple
    /// implementation we map screen sharing to enabling the video
    /// track. A more complete implementation would create a second
    /// video track dedicated to screen content.
    pub async fn start_screen_capture(&self) -> Result<()> {
        // For now, reuse the video track infrastructure.
        self.set_video_enabled(true).await
    }

    /// Stop screen capture on this peer connection. This disables
    /// the video track associated with screen sharing.
    pub async fn stop_screen_capture(&self) -> Result<()> {
        self.set_video_enabled(false).await
    }

    /// Retrieve basic media statistics by summarising the WebRTC stats
    /// report. The report is a map keyed by stat-id with one entry per
    /// transport, codec, candidate-pair and RTP stream. We aggregate the
    /// fields relevant to `MediaStats`:
    ///
    /// * Outbound counts come from `OutboundRTP` entries (one per
    ///   sending track).
    /// * Inbound counts come from `InboundRTP` entries.
    /// * `packets_lost` is reported by the *remote* end via RTCP and
    ///   surfaces as `RemoteInboundRTP`.
    /// * RTT and the live bandwidth estimate come from the nominated
    ///   `CandidatePair`.
    ///
    /// `jitter`, `frame_rate` and `resolution` aren't produced by
    /// webrtc-rs 0.14 (jitter buffer / decoder values are out of scope
    /// since the crate doesn't decode), so they remain at their default
    /// zero/None values.
    pub async fn get_stats(&self) -> Result<MediaStats> {
        let report = self.webrtc_pc.get_stats().await;

        let mut bytes_sent: u64 = 0;
        let mut bytes_received: u64 = 0;
        let mut packets_sent: u64 = 0;
        let mut packets_received: u64 = 0;
        let mut packets_lost: u64 = 0;
        let mut round_trip_time: f64 = 0.0;
        let mut bitrate: u32 = 0;

        for entry in report.reports.values() {
            match entry {
                StatsReportType::OutboundRTP(s) => {
                    bytes_sent = bytes_sent.saturating_add(s.bytes_sent);
                    packets_sent = packets_sent.saturating_add(s.packets_sent);
                }
                StatsReportType::InboundRTP(s) => {
                    bytes_received = bytes_received.saturating_add(s.bytes_received);
                    packets_received = packets_received.saturating_add(s.packets_received);
                }
                StatsReportType::RemoteInboundRTP(s) => {
                    if s.packets_lost > 0 {
                        packets_lost = packets_lost.saturating_add(s.packets_lost as u64);
                    }
                    if round_trip_time == 0.0 {
                        if let Some(rtt) = s.round_trip_time {
                            round_trip_time = rtt;
                        }
                    }
                }
                StatsReportType::CandidatePair(s) if s.nominated => {
                    if s.current_round_trip_time > 0.0 {
                        round_trip_time = s.current_round_trip_time;
                    }
                    if s.available_outgoing_bitrate > 0.0 {
                        bitrate = s.available_outgoing_bitrate as u32;
                    }
                }
                _ => {}
            }
        }

        Ok(MediaStats {
            bytes_sent,
            bytes_received,
            packets_sent,
            packets_received,
            packets_lost,
            jitter: 0.0,
            round_trip_time,
            bitrate,
            frame_rate: None,
            resolution: None,
        })
    }

    /// Hand a remote ICE candidate to the underlying transport so it
    /// can be paired against local candidates during connectivity
    /// checks.
    pub async fn add_ice_candidate(&self, candidate: ICECandidate) -> Result<()> {
        let init = RTCIceCandidateInit {
            candidate: candidate.candidate,
            sdp_mid: Some(candidate.sdp_mid),
            sdp_mline_index: Some(candidate.sdp_mline_index as u16),
            username_fragment: None,
        };
        self.webrtc_pc.add_ice_candidate(init).await
            .context("Failed to add ICE candidate")?;
        Ok(())
    }

    /// Create an SDP offer and install it as the local description so
    /// ICE gathering can begin. Returns the SDP string the caller is
    /// expected to forward to the remote peer over the signalling
    /// channel.
    pub async fn create_offer(&self) -> Result<String> {
        let offer = self.webrtc_pc.create_offer(None).await
            .context("Failed to create SDP offer")?;
        self.webrtc_pc.set_local_description(offer.clone()).await
            .context("Failed to set local description for offer")?;
        Ok(offer.sdp)
    }

    /// Create an answer SDP in response to an offer.
    pub async fn create_answer(&self, offer: &str) -> Result<String> {
        // webrtc 0.14 doesn't allow direct struct-literal construction
        // of RTCSessionDescription — use the typed constructors instead.
        let remote_desc = RTCSessionDescription::offer(offer.to_string())
            .context("Invalid SDP offer")?;
        self.webrtc_pc.set_remote_description(remote_desc).await
            .context("Failed to set remote offer description")?;
        let answer = self.webrtc_pc.create_answer(None).await
            .context("Failed to create SDP answer")?;
        self.webrtc_pc.set_local_description(answer.clone()).await
            .context("Failed to set local description for answer")?;
        Ok(answer.sdp)
    }

    /// Set the remote SDP description, expected to be an answer to a
    /// previously generated local offer.
    pub async fn set_remote_description(&self, description: &str) -> Result<()> {
        let remote_desc = RTCSessionDescription::answer(description.to_string())
            .context("Invalid SDP answer")?;
        self.webrtc_pc.set_remote_description(remote_desc).await
            .context("Failed to set remote description")?;
        Ok(())
    }

    /// Apply a bandwidth limit in kilobits per second. No behaviour in
    /// the stub.
    pub async fn set_bandwidth_limit(&self, _limit_kbps: u32) -> Result<()> {
        Ok(())
    }

    /// Toggle noise suppression. No behaviour in the stub.
    pub async fn set_noise_suppression(&self, _enabled: bool) -> Result<()> {
        Ok(())
    }

    /// Toggle echo cancellation. No behaviour in the stub.
    pub async fn set_echo_cancellation(&self, _enabled: bool) -> Result<()> {
        Ok(())
    }
}
