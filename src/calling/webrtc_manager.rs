use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::identity::identity_key::IdentityId;
use crate::calling::call_manager::CallId;
use crate::calling::media_encryption::MediaKey;
use crate::calling::peer_connection::{PeerConnection, PeerConnectionState, ICECandidate};
use crate::calling::signaling::TurnServer;

/// WebRTC manager for handling real-time media communication
pub struct WebRTCManager {
    /// Active peer connections
    peer_connections: Arc<RwLock<HashMap<(CallId, IdentityId), PeerConnection>>>,
    /// WebRTC configuration
    config: WebRTCConfig,
    /// Media devices manager
    media_devices: MediaDevicesManager,
    /// ICE candidate cache
    ice_candidates: Arc<RwLock<HashMap<(CallId, IdentityId), Vec<ICECandidate>>>>,
}

/// WebRTC configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct WebRTCConfig {
    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,
    /// TURN servers for relay
    pub turn_servers: Vec<TurnServer>,
    /// Enable DTLS for secure transport
    pub enable_dtls: bool,
    /// Enable SRTP for media encryption
    pub enable_srtp: bool,
}

/// Media devices manager
pub struct MediaDevicesManager {
    /// Available audio input devices
    audio_inputs: Vec<MediaDevice>,
    /// Available video input devices
    video_inputs: Vec<MediaDevice>,
    /// Available audio output devices
    audio_outputs: Vec<MediaDevice>,
    /// Current device selections
    current_devices: CurrentDevices,
}

/// Media device information
#[derive(Clone, Serialize, Deserialize)]
pub struct MediaDevice {
    pub id: String,
    pub name: String,
    pub device_type: MediaDeviceType,
    pub is_default: bool,
    pub capabilities: DeviceCapabilities,
}

/// Types of media devices
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaDeviceType {
    AudioInput,
    VideoInput,
    AudioOutput,
}

/// Device capabilities
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// Supported audio sample rates
    pub audio_sample_rates: Vec<u32>,
    /// Supported video resolutions
    pub video_resolutions: Vec<(u32, u32)>,
    /// Supported video frame rates
    pub video_frame_rates: Vec<u32>,
    /// Supported audio codecs
    pub audio_codecs: Vec<String>,
    /// Supported video codecs
    pub video_codecs: Vec<String>,
}

/// Currently selected devices
#[derive(Clone, Serialize, Deserialize)]
pub struct CurrentDevices {
    pub audio_input: Option<String>,
    pub video_input: Option<String>,
    pub audio_output: Option<String>,
}

/// Media stream configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct MediaStreamConfig {
    pub audio_enabled: bool,
    pub video_enabled: bool,
    pub screen_share_enabled: bool,
    pub audio_constraints: AudioConstraints,
    pub video_constraints: VideoConstraints,
}

/// Audio constraints for media capture
#[derive(Clone, Serialize, Deserialize)]
pub struct AudioConstraints {
    pub sample_rate: Option<u32>,
    pub channels: Option<u32>,
    pub echo_cancellation: bool,
    pub noise_suppression: bool,
    pub auto_gain_control: bool,
}

/// Video constraints for media capture
#[derive(Clone, Serialize, Deserialize)]
pub struct VideoConstraints {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub frame_rate: Option<u32>,
    pub facing_mode: Option<FacingMode>,
}

/// Camera facing mode
#[derive(Clone, Serialize, Deserialize)]
pub enum FacingMode {
    User,        // Front camera
    Environment, // Back camera
}

/// RTP codec configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct CodecConfig {
    pub name: String,
    pub payload_type: u8,
    pub clock_rate: u32,
    pub channels: Option<u32>,
    pub parameters: HashMap<String, String>,
}

/// Media statistics
#[derive(Clone, Serialize, Deserialize)]
pub struct MediaStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub jitter: f64,
    pub round_trip_time: f64,
    pub bitrate: u32,
    pub frame_rate: Option<u32>,
    pub resolution: Option<(u32, u32)>,
}

impl WebRTCManager {
    /// Create a new WebRTC manager
    pub async fn new(config: WebRTCConfig) -> Result<Self> {
        let media_devices = MediaDevicesManager::new().await?;
        
        Ok(WebRTCManager {
            peer_connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            media_devices,
            ice_candidates: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Create a new peer connection
    pub async fn create_peer_connection(
        &self,
        call_id: CallId,
        participant: IdentityId,
        media_key: MediaKey,
    ) -> Result<()> {
        let peer_connection = PeerConnection::new(
            self.config.clone(),
            media_key,
            call_id,
            participant,
        ).await?;
        
        let mut connections = self.peer_connections.write().await;
        connections.insert((call_id, participant), peer_connection);
        
        Ok(())
    }
    
    /// Close a peer connection
    pub async fn close_peer_connection(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let mut connections = self.peer_connections.write().await;
        if let Some(mut connection) = connections.remove(&(call_id, participant)) {
            connection.close().await?;
        }
        
        // Clean up ICE candidates
        let mut ice_candidates = self.ice_candidates.write().await;
        ice_candidates.remove(&(call_id, participant));
        
        Ok(())
    }
    
    /// Set audio enabled/disabled for a participant
    pub async fn set_audio_enabled(
        &self,
        call_id: CallId,
        participant: IdentityId,
        enabled: bool,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.set_audio_enabled(enabled).await?;
        }
        Ok(())
    }
    
    /// Set video enabled/disabled for a participant
    pub async fn set_video_enabled(
        &self,
        call_id: CallId,
        participant: IdentityId,
        enabled: bool,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.set_video_enabled(enabled).await?;
        }
        Ok(())
    }
    
    /// Start screen capture for a participant
    pub async fn start_screen_capture(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.start_screen_capture().await?;
        }
        Ok(())
    }
    
    /// Stop screen capture for a participant
    pub async fn stop_screen_capture(&self, call_id: CallId, participant: IdentityId) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.stop_screen_capture().await?;
        }
        Ok(())
    }
    
    /// Get media statistics for a connection
    pub async fn get_media_stats(
        &self,
        call_id: CallId,
        participant: IdentityId,
    ) -> Result<MediaStats> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.get_stats().await
        } else {
            Err(anyhow::anyhow!("Peer connection not found"))
        }
    }
    
    /// Add ICE candidate
    pub async fn add_ice_candidate(
        &self,
        call_id: CallId,
        participant: IdentityId,
        candidate: ICECandidate,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.add_ice_candidate(candidate).await?;
        } else {
            // Store candidate for later if connection doesn't exist yet
            let mut ice_candidates = self.ice_candidates.write().await;
            ice_candidates
                .entry((call_id, participant))
                .or_insert_with(Vec::new)
                .push(candidate);
        }
        Ok(())
    }
    
    /// Create offer for initiating connection
    pub async fn create_offer(
        &self,
        call_id: CallId,
        participant: IdentityId,
    ) -> Result<String> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.create_offer().await
        } else {
            Err(anyhow::anyhow!("Peer connection not found"))
        }
    }
    
    /// Create answer for responding to offer
    pub async fn create_answer(
        &self,
        call_id: CallId,
        participant: IdentityId,
        offer: &str,
    ) -> Result<String> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.create_answer(offer).await
        } else {
            Err(anyhow::anyhow!("Peer connection not found"))
        }
    }
    
    /// Set remote description
    pub async fn set_remote_description(
        &self,
        call_id: CallId,
        participant: IdentityId,
        description: &str,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.set_remote_description(description).await?;
            
            // Add any cached ICE candidates
            let mut ice_candidates = self.ice_candidates.write().await;
            if let Some(candidates) = ice_candidates.remove(&(call_id, participant)) {
                for candidate in candidates {
                    connection.add_ice_candidate(candidate).await?;
                }
            }
        }
        Ok(())
    }
    
    /// Get available media devices
    pub async fn get_media_devices(&self) -> Result<Vec<MediaDevice>> {
        self.media_devices.get_devices().await
    }
    
    /// Set current media devices
    pub async fn set_media_devices(&mut self, devices: CurrentDevices) -> Result<()> {
        self.media_devices.set_current_devices(devices).await
    }
    
    /// Get supported codecs
    pub fn get_supported_codecs(&self) -> Vec<CodecConfig> {
        vec![
            // Audio codecs
            CodecConfig {
                name: "opus".to_string(),
                payload_type: 111,
                clock_rate: 48000,
                channels: Some(2),
                parameters: HashMap::new(),
            },
            CodecConfig {
                name: "PCMU".to_string(),
                payload_type: 0,
                clock_rate: 8000,
                channels: Some(1),
                parameters: HashMap::new(),
            },
            CodecConfig {
                name: "PCMA".to_string(),
                payload_type: 8,
                clock_rate: 8000,
                channels: Some(1),
                parameters: HashMap::new(),
            },
            // Video codecs
            CodecConfig {
                name: "VP8".to_string(),
                payload_type: 96,
                clock_rate: 90000,
                channels: None,
                parameters: HashMap::new(),
            },
            CodecConfig {
                name: "VP9".to_string(),
                payload_type: 98,
                clock_rate: 90000,
                channels: None,
                parameters: HashMap::new(),
            },
            CodecConfig {
                name: "H264".to_string(),
                payload_type: 102,
                clock_rate: 90000,
                channels: None,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("profile-level-id".to_string(), "42e01f".to_string());
                    params
                },
            },
        ]
    }
    
    /// Configure bandwidth limits
    pub async fn set_bandwidth_limit(
        &self,
        call_id: CallId,
        participant: IdentityId,
        limit_kbps: u32,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.set_bandwidth_limit(limit_kbps).await?;
        }
        Ok(())
    }
    
    /// Enable/disable noise suppression
    pub async fn set_noise_suppression(
        &self,
        call_id: CallId,
        participant: IdentityId,
        enabled: bool,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.set_noise_suppression(enabled).await?;
        }
        Ok(())
    }
    
    /// Enable/disable echo cancellation
    pub async fn set_echo_cancellation(
        &self,
        call_id: CallId,
        participant: IdentityId,
        enabled: bool,
    ) -> Result<()> {
        let connections = self.peer_connections.read().await;
        if let Some(connection) = connections.get(&(call_id, participant)) {
            connection.set_echo_cancellation(enabled).await?;
        }
        Ok(())
    }
}

impl MediaDevicesManager {
    /// Create a new media devices manager
    pub async fn new() -> Result<Self> {
        let mut manager = MediaDevicesManager {
            audio_inputs: Vec::new(),
            video_inputs: Vec::new(),
            audio_outputs: Vec::new(),
            current_devices: CurrentDevices {
                audio_input: None,
                video_input: None,
                audio_output: None,
            },
        };
        
        manager.refresh_devices().await?;
        Ok(manager)
    }
    
    /// Refresh the list of available devices
    pub async fn refresh_devices(&mut self) -> Result<()> {
        // This would interface with the actual media device APIs
        // For now, we'll create some mock devices
        
        self.audio_inputs = vec![
            MediaDevice {
                id: "default_audio_input".to_string(),
                name: "Default Microphone".to_string(),
                device_type: MediaDeviceType::AudioInput,
                is_default: true,
                capabilities: DeviceCapabilities {
                    audio_sample_rates: vec![8000, 16000, 44100, 48000],
                    video_resolutions: Vec::new(),
                    video_frame_rates: Vec::new(),
                    audio_codecs: vec!["opus".to_string(), "PCMU".to_string()],
                    video_codecs: Vec::new(),
                },
            },
        ];
        
        self.video_inputs = vec![
            MediaDevice {
                id: "default_video_input".to_string(),
                name: "Default Camera".to_string(),
                device_type: MediaDeviceType::VideoInput,
                is_default: true,
                capabilities: DeviceCapabilities {
                    audio_sample_rates: Vec::new(),
                    video_resolutions: vec![(640, 480), (1280, 720), (1920, 1080)],
                    video_frame_rates: vec![15, 30, 60],
                    audio_codecs: Vec::new(),
                    video_codecs: vec!["VP8".to_string(), "VP9".to_string(), "H264".to_string()],
                },
            },
        ];
        
        self.audio_outputs = vec![
            MediaDevice {
                id: "default_audio_output".to_string(),
                name: "Default Speaker".to_string(),
                device_type: MediaDeviceType::AudioOutput,
                is_default: true,
                capabilities: DeviceCapabilities {
                    audio_sample_rates: vec![8000, 16000, 44100, 48000],
                    video_resolutions: Vec::new(),
                    video_frame_rates: Vec::new(),
                    audio_codecs: vec!["opus".to_string(), "PCMU".to_string()],
                    video_codecs: Vec::new(),
                },
            },
        ];
        
        // Set defaults if not already set
        if self.current_devices.audio_input.is_none() {
            self.current_devices.audio_input = Some("default_audio_input".to_string());
        }
        if self.current_devices.video_input.is_none() {
            self.current_devices.video_input = Some("default_video_input".to_string());
        }
        if self.current_devices.audio_output.is_none() {
            self.current_devices.audio_output = Some("default_audio_output".to_string());
        }
        
        Ok(())
    }
    
    /// Get all available devices
    pub async fn get_devices(&self) -> Result<Vec<MediaDevice>> {
        let mut devices = Vec::new();
        devices.extend(self.audio_inputs.clone());
        devices.extend(self.video_inputs.clone());
        devices.extend(self.audio_outputs.clone());
        Ok(devices)
    }
    
    /// Get devices by type
    pub async fn get_devices_by_type(&self, device_type: MediaDeviceType) -> Result<Vec<MediaDevice>> {
        let devices = match device_type {
            MediaDeviceType::AudioInput => self.audio_inputs.clone(),
            MediaDeviceType::VideoInput => self.video_inputs.clone(),
            MediaDeviceType::AudioOutput => self.audio_outputs.clone(),
        };
        Ok(devices)
    }
    
    /// Set current devices
    pub async fn set_current_devices(&mut self, devices: CurrentDevices) -> Result<()> {
        // Validate device IDs exist
        if let Some(ref audio_input) = devices.audio_input {
            if !self.audio_inputs.iter().any(|d| d.id == *audio_input) {
                return Err(anyhow::anyhow!("Invalid audio input device ID"));
            }
        }
        
        if let Some(ref video_input) = devices.video_input {
            if !self.video_inputs.iter().any(|d| d.id == *video_input) {
                return Err(anyhow::anyhow!("Invalid video input device ID"));
            }
        }
        
        if let Some(ref audio_output) = devices.audio_output {
            if !self.audio_outputs.iter().any(|d| d.id == *audio_output) {
                return Err(anyhow::anyhow!("Invalid audio output device ID"));
            }
        }
        
        self.current_devices = devices;
        Ok(())
    }
    
    /// Get current devices
    pub fn get_current_devices(&self) -> &CurrentDevices {
        &self.current_devices
    }
}

impl Default for MediaStreamConfig {
    fn default() -> Self {
        MediaStreamConfig {
            audio_enabled: true,
            video_enabled: false,
            screen_share_enabled: false,
            audio_constraints: AudioConstraints::default(),
            video_constraints: VideoConstraints::default(),
        }
    }
}

impl Default for AudioConstraints {
    fn default() -> Self {
        AudioConstraints {
            sample_rate: Some(48000),
            channels: Some(1),
            echo_cancellation: true,
            noise_suppression: true,
            auto_gain_control: true,
        }
    }
}

impl Default for VideoConstraints {
    fn default() -> Self {
        VideoConstraints {
            width: Some(1280),
            height: Some(720),
            frame_rate: Some(30),
            facing_mode: Some(FacingMode::User),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_webrtc_manager_creation() {
        let config = WebRTCConfig {
            stun_servers: vec!["stun:stun.l.google.com:19302".to_string()],
            turn_servers: Vec::new(),
            enable_dtls: true,
            enable_srtp: true,
        };
        
        let webrtc_manager = WebRTCManager::new(config).await.expect("Should create WebRTC manager");
        
        let devices = webrtc_manager.get_media_devices().await.expect("Should get devices");
        assert!(!devices.is_empty());
        
        let audio_devices: Vec<_> = devices.iter()
            .filter(|d| d.device_type == MediaDeviceType::AudioInput)
            .collect();
        assert!(!audio_devices.is_empty());
    }
    
    #[tokio::test]
    async fn test_media_devices_manager() {
        let mut manager = MediaDevicesManager::new().await.expect("Should create manager");
        
        let devices = manager.get_devices().await.expect("Should get devices");
        assert!(!devices.is_empty());
        
        let audio_inputs = manager.get_devices_by_type(MediaDeviceType::AudioInput).await
            .expect("Should get audio inputs");
        assert!(!audio_inputs.is_empty());
        
        let current_devices = manager.get_current_devices();
        assert!(current_devices.audio_input.is_some());
    }
    
    #[test]
    fn test_supported_codecs() {
        let config = WebRTCConfig {
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            enable_dtls: true,
            enable_srtp: true,
        };
        
        // Create a mock WebRTC manager for testing
        let webrtc_manager = WebRTCManager {
            peer_connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            media_devices: MediaDevicesManager {
                audio_inputs: Vec::new(),
                video_inputs: Vec::new(),
                audio_outputs: Vec::new(),
                current_devices: CurrentDevices {
                    audio_input: None,
                    video_input: None,
                    audio_output: None,
                },
            },
            ice_candidates: Arc::new(RwLock::new(HashMap::new())),
        };
        
        let codecs = webrtc_manager.get_supported_codecs();
        assert!(!codecs.is_empty());
        
        let opus_codec = codecs.iter().find(|c| c.name == "opus");
        assert!(opus_codec.is_some());
        
        let vp8_codec = codecs.iter().find(|c| c.name == "VP8");
        assert!(vp8_codec.is_some());
    }
}
