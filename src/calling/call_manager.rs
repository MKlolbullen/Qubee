use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};

use crate::calling::media_encryption::MediaEncryption;
use crate::calling::signaling::{SignalingMessage, SignalingTransport};
use crate::calling::webrtc_manager::{WebRTCConfig, WebRTCManager};
use crate::groups::group_manager::GroupId;
use crate::identity::contact_manager::ContactManager;
use crate::identity::identity_key::{IdentityId, IdentityKey, IdentityKeyPair};

/// Comprehensive call management system
pub struct CallManager {
    /// Active calls
    calls: Arc<RwLock<HashMap<CallId, Call>>>,
    /// WebRTC manager for media handling
    webrtc_manager: WebRTCManager,
    /// Media encryption for secure streams
    media_encryption: MediaEncryption,
    /// Signaling carrier for call setup (loopback in tests, session-
    /// backed in production — see issue #67)
    signaling: Arc<dyn SignalingTransport>,
    /// Event sender for call events
    event_sender: mpsc::UnboundedSender<CallEvent>,
    /// Configuration
    config: CallManagerConfig,
    /// Contact manager for resolving identity keys and display names
    contact_manager: Arc<ContactManager>,
}

/// Individual call instance
#[derive(Clone, Serialize, Deserialize)]
pub struct Call {
    pub id: CallId,
    pub call_type: CallType,
    pub state: CallState,
    pub participants: HashMap<IdentityId, CallParticipant>,
    pub initiator: IdentityId,
    pub group_id: Option<GroupId>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub settings: CallSettings,
    pub quality_stats: CallQualityStats,
}

/// Unique identifier for a call
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallId([u8; 16]);

impl CallId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for CallId {
    fn from(bytes: [u8; 16]) -> Self {
        CallId(bytes)
    }
}

/// Types of calls supported
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallType {
    /// One-on-one voice call
    VoiceCall,
    /// One-on-one video call
    VideoCall,
    /// Group voice call
    GroupVoiceCall,
    /// Group video call
    GroupVideoCall,
    /// Screen sharing session
    ScreenShare,
    /// Conference call with multiple participants
    Conference,
}

/// Current state of a call
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallState {
    /// Call is being initiated
    Initiating,
    /// Waiting for participants to join
    Ringing,
    /// Call is active
    Active,
    /// Call is on hold
    OnHold,
    /// Call is being transferred
    Transferring,
    /// Call has ended normally
    Ended,
    /// Call was cancelled before connection
    Cancelled,
    /// Call failed due to error
    Failed { reason: String },
    /// Call was rejected by participant
    Rejected,
    /// Call timed out
    TimedOut,
}

/// Call participant information
#[derive(Clone, Serialize, Deserialize)]
pub struct CallParticipant {
    pub identity_id: IdentityId,
    pub identity_key: IdentityKey,
    pub display_name: String,
    pub participant_state: ParticipantState,
    pub media_state: MediaState,
    pub connection_quality: ConnectionQuality,
    pub joined_at: Option<u64>,
    pub left_at: Option<u64>,
    pub is_muted: bool,
    pub is_video_enabled: bool,
    pub is_screen_sharing: bool,
}

/// State of a participant in the call
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParticipantState {
    /// Invited but not yet responded
    Invited,
    /// Connecting to the call
    Connecting,
    /// Successfully connected
    Connected,
    /// Temporarily disconnected
    Disconnected,
    /// Left the call
    Left,
    /// Kicked from the call
    Kicked,
}

/// Media state for a participant
#[derive(Clone, Serialize, Deserialize)]
pub struct MediaState {
    pub audio_enabled: bool,
    pub video_enabled: bool,
    pub screen_share_enabled: bool,
    pub audio_codec: Option<String>,
    pub video_codec: Option<String>,
    pub bitrate: Option<u32>,
    pub resolution: Option<(u32, u32)>,
    pub frame_rate: Option<u32>,
}

/// Connection quality metrics
#[derive(Clone, Serialize, Deserialize)]
pub struct ConnectionQuality {
    pub signal_strength: u8, // 0-100
    pub packet_loss: f32,    // percentage
    pub latency: u32,        // milliseconds
    pub jitter: u32,         // milliseconds
    pub bandwidth: u32,      // kbps
    pub quality_score: u8,   // 0-5 (5 = excellent)
}

/// Call settings and preferences
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallSettings {
    pub max_participants: Option<usize>,
    pub require_encryption: bool,
    pub allow_recording: bool,
    pub auto_mute_on_join: bool,
    pub enable_noise_cancellation: bool,
    pub enable_echo_cancellation: bool,
    pub video_quality: VideoQuality,
    pub audio_quality: AudioQuality,
    pub bandwidth_limit: Option<u32>,
}

/// Video quality settings
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum VideoQuality {
    Low,    // 240p
    Medium, // 480p
    High,   // 720p
    HD,     // 1080p
    UHD,    // 4K
    Auto,   // Adaptive based on connection
}

/// Audio quality settings
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum AudioQuality {
    Low,    // 8kHz, mono
    Medium, // 16kHz, mono
    High,   // 48kHz, stereo
    Studio, // 96kHz, stereo
    Auto,   // Adaptive based on connection
}

/// Call quality statistics
#[derive(Clone, Serialize, Deserialize)]
pub struct CallQualityStats {
    pub duration: Option<u64>,
    pub avg_packet_loss: f32,
    pub avg_latency: u32,
    pub avg_jitter: u32,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub reconnection_count: u32,
    pub quality_degradation_events: u32,
}

/// Call events for notifications
#[derive(Clone, Serialize, Deserialize)]
pub enum CallEvent {
    /// New incoming call
    IncomingCall {
        call_id: CallId,
        caller: IdentityId,
        call_type: CallType,
    },
    /// Call state changed
    CallStateChanged {
        call_id: CallId,
        old_state: CallState,
        new_state: CallState,
    },
    /// Participant joined
    ParticipantJoined {
        call_id: CallId,
        participant: IdentityId,
    },
    /// Participant left
    ParticipantLeft {
        call_id: CallId,
        participant: IdentityId,
        reason: String,
    },
    /// Media state changed
    MediaStateChanged {
        call_id: CallId,
        participant: IdentityId,
        media_state: MediaState,
    },
    /// Connection quality changed
    QualityChanged {
        call_id: CallId,
        participant: IdentityId,
        quality: ConnectionQuality,
    },
    /// Call error occurred
    CallError { call_id: CallId, error: String },
}

/// Call manager configuration
#[derive(Clone)]
pub struct CallManagerConfig {
    pub max_concurrent_calls: usize,
    pub call_timeout: Duration,
    pub ring_timeout: Duration,
    pub reconnection_attempts: u32,
    pub enable_p2p_optimization: bool,
    pub stun_servers: Vec<String>,
    pub turn_servers: Vec<TurnServer>,
}

/// TURN server configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

impl CallManager {
    /// Create a new call manager
    /// Create a new call manager.
    ///
    /// `media_root` is the per-call secret both endpoints share (in
    /// Qubee, material derived from the 1:1 session — issue #67); media
    /// keys derive from it so the two sides interoperate. `signaling`
    /// is the carrier for call-setup messages: [`SignalingServer`] for
    /// tests/local runs, the session-backed transport in production.
    ///
    /// [`SignalingServer`]: crate::calling::signaling::SignalingServer
    pub async fn new(
        config: CallManagerConfig,
        event_sender: mpsc::UnboundedSender<CallEvent>,
        media_root: [u8; 32],
        signaling: Arc<dyn SignalingTransport>,
    ) -> Result<Self> {
        let webrtc_config = WebRTCConfig {
            stun_servers: config.stun_servers.clone(),
            turn_servers: config.turn_servers.clone(),
            enable_dtls: true,
            enable_srtp: true,
        };

        let webrtc_manager = WebRTCManager::new(webrtc_config).await?;
        let media_encryption = MediaEncryption::from_shared_root(media_root);
        let contact_manager = Arc::new(ContactManager::new());

        Ok(CallManager {
            calls: Arc::new(RwLock::new(HashMap::new())),
            webrtc_manager,
            media_encryption,
            signaling,
            event_sender,
            config,
            contact_manager,
        })
    }

    /// Initiate a new call
    pub async fn initiate_call(
        &self,
        initiator: IdentityId,
        participants: Vec<IdentityId>,
        call_type: CallType,
        group_id: Option<GroupId>,
        settings: CallSettings,
    ) -> Result<CallId> {
        let call_id = self.generate_call_id()?;

        // Validate participants
        if participants.is_empty() {
            return Err(anyhow::anyhow!("No participants specified"));
        }

        if let Some(max_participants) = settings.max_participants {
            if participants.len() > max_participants {
                return Err(anyhow::anyhow!("Too many participants"));
            }
        }

        // Check concurrent call limit
        let calls = self.calls.read().await;
        let active_calls = calls
            .values()
            .filter(|call| matches!(call.state, CallState::Active | CallState::Ringing))
            .count();

        if active_calls >= self.config.max_concurrent_calls {
            return Err(anyhow::anyhow!("Maximum concurrent calls reached"));
        }
        drop(calls);

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Create call participants
        let mut call_participants = HashMap::new();
        for participant_id in participants {
            let participant = CallParticipant {
                identity_id: participant_id,
                identity_key: self.get_identity_key(participant_id).await?, // Would need to be implemented
                display_name: self.get_display_name(participant_id).await?, // Would need to be implemented
                participant_state: ParticipantState::Invited,
                media_state: MediaState::default(),
                connection_quality: ConnectionQuality::default(),
                joined_at: None,
                left_at: None,
                is_muted: settings.auto_mute_on_join,
                is_video_enabled: matches!(
                    call_type,
                    CallType::VideoCall | CallType::GroupVideoCall
                ),
                is_screen_sharing: false,
            };
            call_participants.insert(participant_id, participant);
        }

        let call = Call {
            id: call_id,
            call_type,
            state: CallState::Initiating,
            participants: call_participants,
            initiator,
            group_id,
            created_at: current_time,
            started_at: None,
            ended_at: None,
            settings,
            quality_stats: CallQualityStats::default(),
        };

        // Store the call
        let mut calls = self.calls.write().await;
        calls.insert(call_id, call);
        drop(calls);

        // Send invitations to participants
        self.send_call_invitations(call_id).await?;

        // Update call state to ringing
        self.update_call_state(call_id, CallState::Ringing).await?;

        // Start ring timeout
        self.start_ring_timeout(call_id).await;

        Ok(call_id)
    }

    /// Entry point for a signaling payload received from `from`.
    ///
    /// The carrier (the encrypted 1:1 session — issue #67) hands the
    /// decrypted bytes here; this decodes them and dispatches to the
    /// matching handler. Undecodable input fails closed.
    pub async fn handle_inbound_signaling(&self, from: IdentityId, payload: &[u8]) -> Result<()> {
        let message = SignalingMessage::from_bytes(payload)
            .map_err(|e| anyhow::anyhow!("undecodable signaling payload: {e}"))?;
        self.dispatch_signaling(from, message).await
    }

    /// Route a decoded [`SignalingMessage`] to its handler. The
    /// `sender` fields carried in the message identify the remote
    /// endpoint the state applies to.
    async fn dispatch_signaling(&self, _from: IdentityId, message: SignalingMessage) -> Result<()> {
        match message {
            SignalingMessage::CallInvitation {
                call_id,
                caller,
                call_type,
                settings,
            } => {
                self.on_call_invitation(call_id, caller, call_type, settings)
                    .await
            }
            SignalingMessage::HangUp { call_id, sender } => {
                self.on_remote_hangup(call_id, sender).await
            }
            SignalingMessage::IceCandidate {
                call_id,
                candidate,
                sender,
            } => {
                self.webrtc_manager
                    .add_ice_candidate(call_id, sender, candidate)
                    .await
            }
            // Ingest the remote SDP into the peer connection the accept
            // path set up. Generating and sending back an SDP answer
            // (the responder half, which also needs the local identity
            // threaded through) is phase 2c — issue #67.
            SignalingMessage::SdpOffer {
                call_id,
                sdp,
                sender,
            }
            | SignalingMessage::SdpAnswer {
                call_id,
                sdp,
                sender,
            } => {
                self.webrtc_manager
                    .set_remote_description(call_id, sender, &sdp)
                    .await
            }
        }
    }

    /// Handle an inbound call invitation: register the call in the
    /// ringing state with the caller as its remote participant and
    /// surface an [`CallEvent::IncomingCall`] so the app can ring. A
    /// duplicate invitation for a known call is ignored.
    async fn on_call_invitation(
        &self,
        call_id: CallId,
        caller: IdentityId,
        call_type: CallType,
        settings: CallSettings,
    ) -> Result<()> {
        {
            let calls = self.calls.read().await;
            if calls.contains_key(&call_id) {
                return Ok(());
            }
            let active_calls = calls
                .values()
                .filter(|call| matches!(call.state, CallState::Active | CallState::Ringing))
                .count();
            if active_calls >= self.config.max_concurrent_calls {
                return Err(anyhow::anyhow!("Maximum concurrent calls reached"));
            }
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let caller_participant = CallParticipant {
            identity_id: caller,
            identity_key: self.get_identity_key(caller).await?,
            display_name: self.get_display_name(caller).await?,
            participant_state: ParticipantState::Invited,
            media_state: MediaState::default(),
            connection_quality: ConnectionQuality::default(),
            joined_at: None,
            left_at: None,
            is_muted: settings.auto_mute_on_join,
            is_video_enabled: matches!(call_type, CallType::VideoCall | CallType::GroupVideoCall),
            is_screen_sharing: false,
        };

        let mut participants = HashMap::new();
        participants.insert(caller, caller_participant);

        let call = Call {
            id: call_id,
            call_type: call_type.clone(),
            state: CallState::Ringing,
            participants,
            initiator: caller,
            group_id: None,
            created_at: now,
            started_at: None,
            ended_at: None,
            settings,
            quality_stats: CallQualityStats::default(),
        };

        {
            let mut calls = self.calls.write().await;
            // Re-check under the write lock: another inbound frame may
            // have registered this call between the read and the write.
            if calls.contains_key(&call_id) {
                return Ok(());
            }
            calls.insert(call_id, call);
        }

        self.event_sender
            .send(CallEvent::IncomingCall {
                call_id,
                caller,
                call_type,
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

        self.start_ring_timeout(call_id).await;
        Ok(())
    }

    /// Handle a remote hang-up: mark the call ended, tear down the
    /// peer connection to the sender, and emit a leave event. An
    /// unknown call is ignored.
    async fn on_remote_hangup(&self, call_id: CallId, sender: IdentityId) -> Result<()> {
        {
            let mut calls = self.calls.write().await;
            let call = match calls.get_mut(&call_id) {
                Some(call) => call,
                None => return Ok(()),
            };
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            call.state = CallState::Ended;
            call.ended_at = Some(now);
            if let Some(participant_info) = call.participants.get_mut(&sender) {
                participant_info.participant_state = ParticipantState::Left;
                participant_info.left_at = Some(now);
            }
        }

        // Best-effort teardown; a missing connection is not an error.
        let _ = self.close_peer_connection(call_id, sender).await;

        self.event_sender
            .send(CallEvent::ParticipantLeft {
                call_id,
                participant: sender,
                reason: "Remote hang up".to_string(),
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;
        Ok(())
    }

    /// Accept an incoming call
    pub async fn accept_call(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls
            .get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;

        if !call.participants.contains_key(&participant) {
            return Err(anyhow::anyhow!("Participant not invited to call"));
        }

        if call.state != CallState::Ringing {
            return Err(anyhow::anyhow!("Call is not in ringing state"));
        }

        // Update participant state
        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.participant_state = ParticipantState::Connecting;
            participant_info.joined_at =
                Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
        }

        // If this is the first participant to accept, start the call
        let connecting_participants = call
            .participants
            .values()
            .filter(|p| p.participant_state == ParticipantState::Connecting)
            .count();

        if connecting_participants == 1 && call.state == CallState::Ringing {
            call.state = CallState::Active;
            call.started_at = Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
        }

        drop(calls);

        // Establish WebRTC connection
        self.establish_peer_connection(call_id, participant).await?;

        // Send event
        self.event_sender
            .send(CallEvent::ParticipantJoined {
                call_id,
                participant,
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

        Ok(())
    }

    /// Reject an incoming call
    pub async fn reject_call(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls
            .get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;

        if !call.participants.contains_key(&participant) {
            return Err(anyhow::anyhow!("Participant not invited to call"));
        }

        // Update participant state
        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.participant_state = ParticipantState::Left;
            participant_info.left_at =
                Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
        }

        // Check if all participants have rejected
        let active_participants = call
            .participants
            .values()
            .filter(|p| {
                matches!(
                    p.participant_state,
                    ParticipantState::Invited
                        | ParticipantState::Connecting
                        | ParticipantState::Connected
                )
            })
            .count();

        if active_participants == 0 {
            call.state = CallState::Rejected;
            call.ended_at = Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
        }

        drop(calls);

        // Send event
        self.event_sender
            .send(CallEvent::ParticipantLeft {
                call_id,
                participant,
                reason: "Rejected".to_string(),
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

        Ok(())
    }

    /// End a call
    pub async fn end_call(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls
            .get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;

        // If initiator ends the call, end for everyone
        if participant == call.initiator {
            call.state = CallState::Ended;
            call.ended_at = Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());

            // Update all participants
            for participant_info in call.participants.values_mut() {
                if participant_info.participant_state == ParticipantState::Connected {
                    participant_info.participant_state = ParticipantState::Left;
                    participant_info.left_at =
                        Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
                }
            }
        } else {
            // Individual participant leaves
            if let Some(participant_info) = call.participants.get_mut(&participant) {
                participant_info.participant_state = ParticipantState::Left;
                participant_info.left_at =
                    Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
            }

            // Check if any participants remain
            let active_participants = call
                .participants
                .values()
                .filter(|p| p.participant_state == ParticipantState::Connected)
                .count();

            if active_participants <= 1 {
                call.state = CallState::Ended;
                call.ended_at = Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
            }
        }

        drop(calls);

        // Close peer connections
        self.close_peer_connection(call_id, participant).await?;

        // Send event
        self.event_sender
            .send(CallEvent::ParticipantLeft {
                call_id,
                participant,
                reason: "Left call".to_string(),
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

        Ok(())
    }

    /// Toggle mute for a participant.
    ///
    /// The WebRTC track is switched *before* the participant's state is
    /// committed, so a failed media update leaves the stored state and
    /// the actual track in agreement rather than diverging. Full
    /// serialisation of overlapping toggles is tracked in issue #67.
    pub async fn toggle_mute(&self, call_id: CallId, participant: IdentityId) -> Result<bool> {
        let target_muted = {
            let calls = self.calls.read().await;
            let participant_info = calls
                .get(&call_id)
                .ok_or_else(|| anyhow::anyhow!("Call not found"))?
                .participants
                .get(&participant)
                .ok_or_else(|| anyhow::anyhow!("Participant not found in call"))?;
            !participant_info.is_muted
        };

        // Apply to the WebRTC audio track first; on failure nothing is
        // committed and the error propagates.
        self.webrtc_manager
            .set_audio_enabled(call_id, participant, !target_muted)
            .await?;

        let new_state = {
            let mut calls = self.calls.write().await;
            let participant_info = calls
                .get_mut(&call_id)
                .ok_or_else(|| anyhow::anyhow!("Call not found"))?
                .participants
                .get_mut(&participant)
                .ok_or_else(|| anyhow::anyhow!("Participant not found in call"))?;
            participant_info.is_muted = target_muted;
            participant_info.media_state.audio_enabled = !target_muted;
            participant_info.media_state.clone()
        };

        self.event_sender
            .send(CallEvent::MediaStateChanged {
                call_id,
                participant,
                media_state: new_state,
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

        Ok(target_muted)
    }

    /// Toggle video for a participant.
    ///
    /// Same ordering discipline as [`toggle_mute`](Self::toggle_mute):
    /// the track is switched before the state is committed.
    pub async fn toggle_video(&self, call_id: CallId, participant: IdentityId) -> Result<bool> {
        let target_enabled = {
            let calls = self.calls.read().await;
            let participant_info = calls
                .get(&call_id)
                .ok_or_else(|| anyhow::anyhow!("Call not found"))?
                .participants
                .get(&participant)
                .ok_or_else(|| anyhow::anyhow!("Participant not found in call"))?;
            !participant_info.is_video_enabled
        };

        self.webrtc_manager
            .set_video_enabled(call_id, participant, target_enabled)
            .await?;

        let new_state = {
            let mut calls = self.calls.write().await;
            let participant_info = calls
                .get_mut(&call_id)
                .ok_or_else(|| anyhow::anyhow!("Call not found"))?
                .participants
                .get_mut(&participant)
                .ok_or_else(|| anyhow::anyhow!("Participant not found in call"))?;
            participant_info.is_video_enabled = target_enabled;
            participant_info.media_state.video_enabled = target_enabled;
            participant_info.media_state.clone()
        };

        self.event_sender
            .send(CallEvent::MediaStateChanged {
                call_id,
                participant,
                media_state: new_state,
            })
            .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

        Ok(target_enabled)
    }

    /// Start screen sharing
    pub async fn start_screen_share(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls
            .get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;

        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.is_screen_sharing = true;
            participant_info.media_state.screen_share_enabled = true;

            let new_state = participant_info.media_state.clone();
            drop(calls);

            // Start screen capture
            self.webrtc_manager
                .start_screen_capture(call_id, participant)
                .await?;

            // Send event
            self.event_sender
                .send(CallEvent::MediaStateChanged {
                    call_id,
                    participant,
                    media_state: new_state,
                })
                .map_err(|_| anyhow::anyhow!("Failed to send event"))?;

            Ok(())
        } else {
            Err(anyhow::anyhow!("Participant not found in call"))
        }
    }

    /// Get call information
    pub async fn get_call(&self, call_id: CallId) -> Option<Call> {
        let calls = self.calls.read().await;
        calls.get(&call_id).cloned()
    }

    /// Get all active calls
    pub async fn get_active_calls(&self) -> Vec<Call> {
        let calls = self.calls.read().await;
        calls
            .values()
            .filter(|call| matches!(call.state, CallState::Active | CallState::Ringing))
            .cloned()
            .collect()
    }

    /// Update call quality statistics
    pub async fn update_quality_stats(
        &self,
        call_id: CallId,
        participant: IdentityId,
        quality: ConnectionQuality,
    ) -> Result<()> {
        let mut calls = self.calls.write().await;
        if let Some(call) = calls.get_mut(&call_id) {
            if let Some(participant_info) = call.participants.get_mut(&participant) {
                participant_info.connection_quality = quality.clone();

                // Send event
                self.event_sender
                    .send(CallEvent::QualityChanged {
                        call_id,
                        participant,
                        quality,
                    })
                    .map_err(|_| anyhow::anyhow!("Failed to send event"))?;
            }
        }
        Ok(())
    }

    /// Generate a unique call ID
    fn generate_call_id(&self) -> Result<CallId> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)?;
        Ok(CallId(bytes))
    }

    /// Send call invitations to participants
    async fn send_call_invitations(&self, call_id: CallId) -> Result<()> {
        let calls = self.calls.read().await;
        let call = calls
            .get(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;

        for participant_id in call.participants.keys() {
            if *participant_id != call.initiator {
                let message = SignalingMessage::CallInvitation {
                    call_id,
                    caller: call.initiator,
                    call_type: call.call_type.clone(),
                    settings: call.settings.clone(),
                };

                self.signaling.send(*participant_id, message).await?;

                // Send event
                self.event_sender
                    .send(CallEvent::IncomingCall {
                        call_id,
                        caller: call.initiator,
                        call_type: call.call_type.clone(),
                    })
                    .map_err(|_| anyhow::anyhow!("Failed to send event"))?;
            }
        }

        Ok(())
    }

    /// Update call state
    async fn update_call_state(&self, call_id: CallId, new_state: CallState) -> Result<()> {
        let mut calls = self.calls.write().await;
        if let Some(call) = calls.get_mut(&call_id) {
            let old_state = call.state.clone();
            call.state = new_state.clone();

            // Send event
            self.event_sender
                .send(CallEvent::CallStateChanged {
                    call_id,
                    old_state,
                    new_state,
                })
                .map_err(|_| anyhow::anyhow!("Failed to send event"))?;
        }
        Ok(())
    }

    /// Start ring timeout
    async fn start_ring_timeout(&self, call_id: CallId) {
        let calls = self.calls.clone();
        let timeout = self.config.ring_timeout;
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;

            let mut calls = calls.write().await;
            if let Some(call) = calls.get_mut(&call_id) {
                if call.state == CallState::Ringing {
                    call.state = CallState::TimedOut;
                    call.ended_at = Some(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    );

                    let _ = event_sender.send(CallEvent::CallStateChanged {
                        call_id,
                        old_state: CallState::Ringing,
                        new_state: CallState::TimedOut,
                    });
                }
            }
        });
    }

    /// Establish peer connection for a participant
    async fn establish_peer_connection(
        &self,
        call_id: CallId,
        participant: IdentityId,
    ) -> Result<()> {
        // Generate media encryption key
        let media_key = self
            .media_encryption
            .generate_media_key(call_id.as_bytes(), participant.as_ref());

        // Create WebRTC peer connection
        self.webrtc_manager
            .create_peer_connection(call_id, participant, media_key)
            .await?;

        Ok(())
    }

    /// Close peer connection for a participant
    async fn close_peer_connection(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        self.webrtc_manager
            .close_peer_connection(call_id, participant)
            .await?;
        Ok(())
    }

    /// Get identity key for a participant (placeholder)
    async fn get_identity_key(&self, participant: IdentityId) -> Result<IdentityKey> {
        // Try to look up the contact first. If none exists we fall back
        // to generating a fresh identity key pair. This ensures that
        // calls can be initiated against unknown identities in tests and
        // offline scenarios. A production implementation should fetch
        // the remote party's identity from a trusted directory or
        // signalling service instead.
        if let Some(key) = self.contact_manager.get_identity_key(&participant).await {
            return Ok(key);
        }
        // Generate a new identity key pair. Any errors here should be
        // propagated back to the caller.
        let pair = IdentityKeyPair::generate()?;
        Ok(pair.public_key())
    }

    /// Get display name for a participant (placeholder)
    async fn get_display_name(&self, participant: IdentityId) -> Result<String> {
        if let Some(name) = self.contact_manager.get_display_name(&participant).await {
            Ok(name)
        } else {
            // If no contact exists, return a generic placeholder. This
            // mirrors the previous behaviour but goes through the
            // contact manager for consistency.
            Ok("Unknown".to_string())
        }
    }
}

impl Default for MediaState {
    fn default() -> Self {
        MediaState {
            audio_enabled: true,
            video_enabled: false,
            screen_share_enabled: false,
            audio_codec: None,
            video_codec: None,
            bitrate: None,
            resolution: None,
            frame_rate: None,
        }
    }
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        ConnectionQuality {
            signal_strength: 100,
            packet_loss: 0.0,
            latency: 0,
            jitter: 0,
            bandwidth: 0,
            quality_score: 5,
        }
    }
}

impl Default for CallQualityStats {
    fn default() -> Self {
        CallQualityStats {
            duration: None,
            avg_packet_loss: 0.0,
            avg_latency: 0,
            avg_jitter: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            reconnection_count: 0,
            quality_degradation_events: 0,
        }
    }
}

impl Default for CallSettings {
    fn default() -> Self {
        CallSettings {
            max_participants: Some(8),
            require_encryption: true,
            allow_recording: false,
            auto_mute_on_join: false,
            enable_noise_cancellation: true,
            enable_echo_cancellation: true,
            video_quality: VideoQuality::Auto,
            audio_quality: AudioQuality::Auto,
            bandwidth_limit: None,
        }
    }
}

impl Default for CallManagerConfig {
    fn default() -> Self {
        CallManagerConfig {
            max_concurrent_calls: 10,
            call_timeout: Duration::from_secs(300), // 5 minutes
            ring_timeout: Duration::from_secs(60),  // 1 minute
            reconnection_attempts: 3,
            enable_p2p_optimization: true,
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: Vec::new(),
        }
    }
}

impl std::fmt::Display for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl std::fmt::Debug for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CallId({})", hex::encode(&self.0[..8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calling::peer_connection::ICECandidate;
    use crate::calling::signaling::SignalingServer;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_call_creation() {
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
        let config = CallManagerConfig::default();

        // The invite rides the in-process signaling server; an
        // unregistered recipient makes initiate_call fail (correctly —
        // there is nobody to ring). Register the callee before building
        // the manager, then hand the server in as the transport.
        let server = Arc::new(SignalingServer::new().await.unwrap());
        let _callee_inbox = server.register_client(IdentityId::from([2u8; 32])).await;

        let call_manager = CallManager::new(config, event_sender, [7u8; 32], server)
            .await
            .expect("Should create call manager");

        let initiator = IdentityId::from([1u8; 32]);
        let participants = vec![IdentityId::from([2u8; 32])];

        let call_id = call_manager
            .initiate_call(
                initiator,
                participants,
                CallType::VoiceCall,
                None,
                CallSettings::default(),
            )
            .await
            .expect("Should initiate call");

        let call = call_manager
            .get_call(call_id)
            .await
            .expect("Should find call");
        assert_eq!(call.call_type, CallType::VoiceCall);
        assert_eq!(call.initiator, initiator);
        assert_eq!(call.participants.len(), 1);
    }

    async fn manager_with_events() -> (CallManager, mpsc::UnboundedReceiver<CallEvent>) {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        let server = Arc::new(SignalingServer::new().await.unwrap());
        let manager = CallManager::new(
            CallManagerConfig::default(),
            event_sender,
            [7u8; 32],
            server,
        )
        .await
        .expect("build manager");
        (manager, event_receiver)
    }

    #[tokio::test]
    async fn inbound_invitation_rings_and_registers_call() {
        let (manager, mut events) = manager_with_events().await;
        let caller = IdentityId::from([1u8; 32]);
        let call_id = CallId::from([9u8; 16]);

        let payload = SignalingMessage::CallInvitation {
            call_id,
            caller,
            call_type: CallType::VideoCall,
            settings: CallSettings::default(),
        }
        .to_bytes()
        .unwrap();

        manager
            .handle_inbound_signaling(caller, &payload)
            .await
            .expect("invitation handled");

        let call = manager.get_call(call_id).await.expect("call registered");
        assert_eq!(call.state, CallState::Ringing);
        assert_eq!(call.initiator, caller);
        assert!(call.participants.contains_key(&caller));

        assert!(matches!(
            events.try_recv(),
            Ok(CallEvent::IncomingCall { caller: c, .. }) if c == caller
        ));

        // A duplicate invitation for the same call is a no-op, not an error.
        manager
            .handle_inbound_signaling(caller, &payload)
            .await
            .expect("duplicate invitation ignored");
    }

    #[tokio::test]
    async fn inbound_hangup_ends_the_call() {
        let (manager, mut events) = manager_with_events().await;
        let caller = IdentityId::from([1u8; 32]);
        let call_id = CallId::from([9u8; 16]);

        let invite = SignalingMessage::CallInvitation {
            call_id,
            caller,
            call_type: CallType::VoiceCall,
            settings: CallSettings::default(),
        }
        .to_bytes()
        .unwrap();
        manager
            .handle_inbound_signaling(caller, &invite)
            .await
            .unwrap();
        let _incoming = events.try_recv();

        let hangup = SignalingMessage::HangUp {
            call_id,
            sender: caller,
        }
        .to_bytes()
        .unwrap();
        manager
            .handle_inbound_signaling(caller, &hangup)
            .await
            .expect("hangup handled");

        let call = manager.get_call(call_id).await.expect("call still tracked");
        assert_eq!(call.state, CallState::Ended);
        assert!(call.ended_at.is_some());
        assert!(matches!(
            events.try_recv(),
            Ok(CallEvent::ParticipantLeft { participant, .. }) if participant == caller
        ));
    }

    #[tokio::test]
    async fn inbound_hangup_for_unknown_call_is_ignored() {
        let (manager, _events) = manager_with_events().await;
        let payload = SignalingMessage::HangUp {
            call_id: CallId::from([3u8; 16]),
            sender: IdentityId::from([1u8; 32]),
        }
        .to_bytes()
        .unwrap();
        manager
            .handle_inbound_signaling(IdentityId::from([1u8; 32]), &payload)
            .await
            .expect("unknown-call hangup is a no-op");
    }

    #[tokio::test]
    async fn inbound_ice_candidate_before_connection_is_buffered() {
        let (manager, _events) = manager_with_events().await;
        let payload = SignalingMessage::IceCandidate {
            call_id: CallId::from([9u8; 16]),
            candidate: ICECandidate {
                sdp_mid: "audio".to_string(),
                sdp_mline_index: 0,
                candidate: "candidate:1 1 UDP 2130706431 192.0.2.1 3478 typ host".to_string(),
            },
            sender: IdentityId::from([1u8; 32]),
        }
        .to_bytes()
        .unwrap();
        // No peer connection exists yet; the candidate is cached rather
        // than rejected.
        manager
            .handle_inbound_signaling(IdentityId::from([1u8; 32]), &payload)
            .await
            .expect("early ICE candidate buffered");
    }

    #[tokio::test]
    async fn undecodable_signaling_payload_fails_closed() {
        let (manager, _events) = manager_with_events().await;
        assert!(manager
            .handle_inbound_signaling(IdentityId::from([1u8; 32]), b"not a signaling frame")
            .await
            .is_err());
    }
}
