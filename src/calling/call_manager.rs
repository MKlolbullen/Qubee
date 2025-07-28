use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;

use crate::identity::identity_key::{IdentityId, IdentityKey};
use crate::calling::webrtc_manager::{WebRTCManager, WebRTCConfig};
use crate::calling::media_encryption::{MediaEncryption, MediaKey};
use crate::calling::signaling::{SignalingServer, SignalingMessage, SignalingClient};
use crate::calling::peer_connection::{PeerConnection, PeerConnectionState};
use crate::groups::group_manager::GroupId;

/// Comprehensive call management system
pub struct CallManager {
    /// Active calls
    calls: Arc<RwLock<HashMap<CallId, Call>>>,
    /// WebRTC manager for media handling
    webrtc_manager: WebRTCManager,
    /// Media encryption for secure streams
    media_encryption: MediaEncryption,
    /// Signaling server for call setup
    signaling_server: Arc<SignalingServer>,
    /// Event sender for call events
    event_sender: mpsc::UnboundedSender<CallEvent>,
    /// Configuration
    config: CallManagerConfig,
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

/// Types of calls supported
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Clone, Serialize, Deserialize)]
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
#[derive(Clone, Serialize, Deserialize)]
pub enum VideoQuality {
    Low,      // 240p
    Medium,   // 480p
    High,     // 720p
    HD,       // 1080p
    UHD,      // 4K
    Auto,     // Adaptive based on connection
}

/// Audio quality settings
#[derive(Clone, Serialize, Deserialize)]
pub enum AudioQuality {
    Low,      // 8kHz, mono
    Medium,   // 16kHz, mono
    High,     // 48kHz, stereo
    Studio,   // 96kHz, stereo
    Auto,     // Adaptive based on connection
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
    CallError {
        call_id: CallId,
        error: String,
    },
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
    pub async fn new(
        config: CallManagerConfig,
        event_sender: mpsc::UnboundedSender<CallEvent>,
    ) -> Result<Self> {
        let webrtc_config = WebRTCConfig {
            stun_servers: config.stun_servers.clone(),
            turn_servers: config.turn_servers.clone(),
            enable_dtls: true,
            enable_srtp: true,
        };
        
        let webrtc_manager = WebRTCManager::new(webrtc_config).await?;
        let media_encryption = MediaEncryption::new()?;
        let signaling_server = Arc::new(SignalingServer::new().await?);
        
        Ok(CallManager {
            calls: Arc::new(RwLock::new(HashMap::new())),
            webrtc_manager,
            media_encryption,
            signaling_server,
            event_sender,
            config,
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
        let active_calls = calls.values()
            .filter(|call| matches!(call.state, CallState::Active | CallState::Ringing))
            .count();
        
        if active_calls >= self.config.max_concurrent_calls {
            return Err(anyhow::anyhow!("Maximum concurrent calls reached"));
        }
        drop(calls);
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
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
                is_video_enabled: matches!(call_type, CallType::VideoCall | CallType::GroupVideoCall),
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
    
    /// Accept an incoming call
    pub async fn accept_call(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls.get_mut(&call_id)
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
            participant_info.joined_at = Some(SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs());
        }
        
        // If this is the first participant to accept, start the call
        let connecting_participants = call.participants.values()
            .filter(|p| p.participant_state == ParticipantState::Connecting)
            .count();
        
        if connecting_participants == 1 && call.state == CallState::Ringing {
            call.state = CallState::Active;
            call.started_at = Some(SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs());
        }
        
        drop(calls);
        
        // Establish WebRTC connection
        self.establish_peer_connection(call_id, participant).await?;
        
        // Send event
        self.event_sender.send(CallEvent::ParticipantJoined {
            call_id,
            participant,
        }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
        
        Ok(())
    }
    
    /// Reject an incoming call
    pub async fn reject_call(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls.get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;
        
        if !call.participants.contains_key(&participant) {
            return Err(anyhow::anyhow!("Participant not invited to call"));
        }
        
        // Update participant state
        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.participant_state = ParticipantState::Left;
            participant_info.left_at = Some(SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs());
        }
        
        // Check if all participants have rejected
        let active_participants = call.participants.values()
            .filter(|p| matches!(p.participant_state, ParticipantState::Invited | ParticipantState::Connecting | ParticipantState::Connected))
            .count();
        
        if active_participants == 0 {
            call.state = CallState::Rejected;
            call.ended_at = Some(SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs());
        }
        
        drop(calls);
        
        // Send event
        self.event_sender.send(CallEvent::ParticipantLeft {
            call_id,
            participant,
            reason: "Rejected".to_string(),
        }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
        
        Ok(())
    }
    
    /// End a call
    pub async fn end_call(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls.get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;
        
        // If initiator ends the call, end for everyone
        if participant == call.initiator {
            call.state = CallState::Ended;
            call.ended_at = Some(SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs());
            
            // Update all participants
            for participant_info in call.participants.values_mut() {
                if participant_info.participant_state == ParticipantState::Connected {
                    participant_info.participant_state = ParticipantState::Left;
                    participant_info.left_at = Some(SystemTime::now()
                        .duration_since(UNIX_EPOCH)?
                        .as_secs());
                }
            }
        } else {
            // Individual participant leaves
            if let Some(participant_info) = call.participants.get_mut(&participant) {
                participant_info.participant_state = ParticipantState::Left;
                participant_info.left_at = Some(SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs());
            }
            
            // Check if any participants remain
            let active_participants = call.participants.values()
                .filter(|p| p.participant_state == ParticipantState::Connected)
                .count();
            
            if active_participants <= 1 {
                call.state = CallState::Ended;
                call.ended_at = Some(SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs());
            }
        }
        
        drop(calls);
        
        // Close peer connections
        self.close_peer_connection(call_id, participant).await?;
        
        // Send event
        self.event_sender.send(CallEvent::ParticipantLeft {
            call_id,
            participant,
            reason: "Left call".to_string(),
        }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
        
        Ok(())
    }
    
    /// Toggle mute for a participant
    pub async fn toggle_mute(&self, call_id: CallId, participant: IdentityId) -> Result<bool> {
        let mut calls = self.calls.write().await;
        let call = calls.get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;
        
        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.is_muted = !participant_info.is_muted;
            participant_info.media_state.audio_enabled = !participant_info.is_muted;
            
            let new_state = participant_info.media_state.clone();
            drop(calls);
            
            // Update WebRTC audio track
            self.webrtc_manager.set_audio_enabled(call_id, participant, !participant_info.is_muted).await?;
            
            // Send event
            self.event_sender.send(CallEvent::MediaStateChanged {
                call_id,
                participant,
                media_state: new_state,
            }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
            
            Ok(participant_info.is_muted)
        } else {
            Err(anyhow::anyhow!("Participant not found in call"))
        }
    }
    
    /// Toggle video for a participant
    pub async fn toggle_video(&self, call_id: CallId, participant: IdentityId) -> Result<bool> {
        let mut calls = self.calls.write().await;
        let call = calls.get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;
        
        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.is_video_enabled = !participant_info.is_video_enabled;
            participant_info.media_state.video_enabled = participant_info.is_video_enabled;
            
            let new_state = participant_info.media_state.clone();
            drop(calls);
            
            // Update WebRTC video track
            self.webrtc_manager.set_video_enabled(call_id, participant, participant_info.is_video_enabled).await?;
            
            // Send event
            self.event_sender.send(CallEvent::MediaStateChanged {
                call_id,
                participant,
                media_state: new_state,
            }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
            
            Ok(participant_info.is_video_enabled)
        } else {
            Err(anyhow::anyhow!("Participant not found in call"))
        }
    }
    
    /// Start screen sharing
    pub async fn start_screen_share(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut calls = self.calls.write().await;
        let call = calls.get_mut(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;
        
        if let Some(participant_info) = call.participants.get_mut(&participant) {
            participant_info.is_screen_sharing = true;
            participant_info.media_state.screen_share_enabled = true;
            
            let new_state = participant_info.media_state.clone();
            drop(calls);
            
            // Start screen capture
            self.webrtc_manager.start_screen_capture(call_id, participant).await?;
            
            // Send event
            self.event_sender.send(CallEvent::MediaStateChanged {
                call_id,
                participant,
                media_state: new_state,
            }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
            
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
        calls.values()
            .filter(|call| matches!(call.state, CallState::Active | CallState::Ringing))
            .cloned()
            .collect()
    }
    
    /// Update call quality statistics
    pub async fn update_quality_stats(&self, call_id: CallId, participant: IdentityId, quality: ConnectionQuality) -> Result<()> {
        let mut calls = self.calls.write().await;
        if let Some(call) = calls.get_mut(&call_id) {
            if let Some(participant_info) = call.participants.get_mut(&participant) {
                participant_info.connection_quality = quality.clone();
                
                // Send event
                self.event_sender.send(CallEvent::QualityChanged {
                    call_id,
                    participant,
                    quality,
                }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
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
        let call = calls.get(&call_id)
            .ok_or_else(|| anyhow::anyhow!("Call not found"))?;
        
        for participant_id in call.participants.keys() {
            if *participant_id != call.initiator {
                let message = SignalingMessage::CallInvitation {
                    call_id,
                    caller: call.initiator,
                    call_type: call.call_type.clone(),
                    settings: call.settings.clone(),
                };
                
                self.signaling_server.send_message(*participant_id, message).await?;
                
                // Send event
                self.event_sender.send(CallEvent::IncomingCall {
                    call_id,
                    caller: call.initiator,
                    call_type: call.call_type.clone(),
                }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
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
            self.event_sender.send(CallEvent::CallStateChanged {
                call_id,
                old_state,
                new_state,
            }).map_err(|_| anyhow::anyhow!("Failed to send event"))?;
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
                    call.ended_at = Some(SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs());
                    
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
    async fn establish_peer_connection(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        // Generate media encryption key
        let media_key = self.media_encryption.generate_media_key(call_id, participant)?;
        
        // Create WebRTC peer connection
        self.webrtc_manager.create_peer_connection(call_id, participant, media_key).await?;
        
        Ok(())
    }
    
    /// Close peer connection for a participant
    async fn close_peer_connection(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        self.webrtc_manager.close_peer_connection(call_id, participant).await?;
        Ok(())
    }
    
    /// Get identity key for a participant (placeholder)
    async fn get_identity_key(&self, _participant: IdentityId) -> Result<IdentityKey> {
        // This would be implemented to retrieve the identity key from storage
        todo!("Implement identity key retrieval")
    }
    
    /// Get display name for a participant (placeholder)
    async fn get_display_name(&self, _participant: IdentityId) -> Result<String> {
        // This would be implemented to retrieve the display name from contacts
        Ok("Unknown".to_string())
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
    use tokio::sync::mpsc;
    
    #[tokio::test]
    async fn test_call_creation() {
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
        let config = CallManagerConfig::default();
        let call_manager = CallManager::new(config, event_sender).await.expect("Should create call manager");
        
        let initiator = IdentityId::from([1u8; 32]);
        let participants = vec![IdentityId::from([2u8; 32])];
        
        let call_id = call_manager.initiate_call(
            initiator,
            participants,
            CallType::VoiceCall,
            None,
            CallSettings::default(),
        ).await.expect("Should initiate call");
        
        let call = call_manager.get_call(call_id).await.expect("Should find call");
        assert_eq!(call.call_type, CallType::VoiceCall);
        assert_eq!(call.initiator, initiator);
        assert_eq!(call.participants.len(), 1);
    }
}
