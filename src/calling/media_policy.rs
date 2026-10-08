//! Shared limits for the gated calling stack.
//!
//! Android capture is 48 kHz mono Opus (`AudioCallEngine`). WebRTC track
//! metadata and the negotiated codec must describe that pipeline, not a
//! stereo format the encoder does not emit. Every untrusted frame and
//! signaling string is rejected before it is copied into a queue.

use anyhow::{bail, Result};

/// Clock rate of the Opus capture path. Must match `AudioCallEngine.SAMPLE_RATE`.
pub const OPUS_CLOCK_RATE: u32 = 48_000;

/// Channel count of the Opus capture path. Must match the mono `AudioRecord`
/// format. Stereo is not advertised unless an encoder that actually emits
/// stereo is wired.
pub const OPUS_CHANNELS: u16 = 1;

/// fmtp line advertised with Opus. `stereo=0` / `sprop-stereo=0` keep a
/// remote peer from assuming a two-channel packetization we do not produce.
pub const OPUS_FMTP: &str = "minptime=10;useinbandfec=1;stereo=0;sprop-stereo=0";

/// Hard cap for one encoded audio payload (outbound sample or inbound RTP).
///
/// RFC 6716 limits an Opus frame to 1275 bytes. 2048 leaves a little room
/// for a future packetization quirk without accepting a multi-megabyte
/// "audio" blob from a hostile peer or a buggy app.
pub const MAX_AUDIO_FRAME_BYTES: usize = 2048;

/// Hard cap for one inbound RTP video payload or outbound video sample.
/// webrtc-rs delivers individual RTP packets, not reassembled frames, so
/// this is a packet bound, not a keyframe bound.
pub const MAX_VIDEO_FRAME_BYTES: usize = 16 * 1024;

/// Hard cap for one complete VP8 access unit, either outbound from the
/// camera encoder or inbound after RTP reassembly. Larger than one RTP
/// packet so a keyframe can span packets, still small enough that a
/// missing marker cannot retain an unbounded buffer.
pub const MAX_VIDEO_ACCESS_UNIT_BYTES: usize = 128 * 1024;

/// Real-time playback window: 12 × 20 ms = 240 ms. Matches the Android
/// playback queue. A slower consumer drops the oldest frame.
pub const REMOTE_MEDIA_QUEUE_CAPACITY: usize = 12;

/// Largest signaling blob accepted before bincode allocation.
pub const MAX_SIGNALING_FRAME_BYTES: usize = 64 * 1024;

/// Largest SDP offer or answer installed on a peer connection.
pub const MAX_SDP_BYTES: usize = 32 * 1024;

/// Largest ICE candidate or SDP mid string retained from a peer.
pub const MAX_ICE_TEXT_BYTES: usize = 1024;

/// Trickle candidates cached before the peer connection exists.
pub const MAX_CACHED_ICE_PER_PEER: usize = 16;

pub fn check_audio_frame(data: &[u8]) -> Result<()> {
    check_bounded("audio frame", data, MAX_AUDIO_FRAME_BYTES)
}

pub fn check_video_frame(data: &[u8]) -> Result<()> {
    check_bounded("video frame", data, MAX_VIDEO_FRAME_BYTES)
}

pub fn check_video_access_unit(data: &[u8]) -> Result<()> {
    check_bounded("video access unit", data, MAX_VIDEO_ACCESS_UNIT_BYTES)
}

fn check_bounded(label: &str, data: &[u8], max: usize) -> Result<()> {
    if data.is_empty() || data.len() > max {
        bail!("{label} length {} is outside 1..={max}", data.len());
    }
    Ok(())
}

pub fn check_sdp(sdp: &str) -> Result<()> {
    if sdp.is_empty() || sdp.len() > MAX_SDP_BYTES {
        bail!("sdp length {} is outside 1..={MAX_SDP_BYTES}", sdp.len());
    }
    Ok(())
}

pub fn check_ice_text(field: &str, value: &str) -> Result<()> {
    if value.len() > MAX_ICE_TEXT_BYTES {
        bail!(
            "{field} length {} exceeds {MAX_ICE_TEXT_BYTES}",
            value.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_cap_covers_opus_and_rejects_hostile_sizes() {
        assert!(check_audio_frame(&[0u8; 16]).is_ok());
        assert!(check_audio_frame(&[]).is_err());
        assert!(check_audio_frame(&[0u8; MAX_AUDIO_FRAME_BYTES + 1]).is_err());
        assert!(check_audio_frame(&[0u8; 1275]).is_ok());
        assert!(check_video_frame(&[0u8; MAX_VIDEO_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn shipped_opus_profile_is_android_mono() {
        assert_eq!(OPUS_CLOCK_RATE, 48_000);
        assert_eq!(OPUS_CHANNELS, 1);
        assert!(OPUS_FMTP.contains("stereo=0"));
        assert!(OPUS_FMTP.contains("sprop-stereo=0"));
        assert!(!OPUS_FMTP.contains("stereo=1"));
    }
}
