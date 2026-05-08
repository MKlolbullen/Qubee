//! Process-wide registry of video input devices the embedder has
//! enumerated for us. The Rust core has no portable way to discover
//! cameras (cpal is audio-only; v4l/AVFoundation/Camera2/MediaFoundation
//! all live in the platform layer), so the Android app calls in via
//! [`crate::jni_api`]'s `nativeRegisterVideoInputs` after walking
//! Camera2 — and the calling module's `MediaDevicesManager` reads the
//! registry on `refresh_devices` instead of returning a hand-written
//! mock list.
//!
//! Audio is the other axis. cpal handles it directly inside the
//! calling module, so this registry only carries video.
//!
//! Lives at the crate root (rather than under `calling/`) so the
//! storage type stays available to the JNI bridge regardless of
//! whether the `calling` feature is enabled. With the feature off the
//! registry just sits unread — no worse than before.

use serde::Deserialize;
use std::sync::{OnceLock, RwLock};

/// Which way a camera points, when the platform tells us. Maps 1:1
/// to Android's `LENS_FACING_*` constants and AVFoundation's
/// `AVCaptureDevicePosition`.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VideoFacing {
    /// User-facing camera (selfie).
    Front,
    /// Environment-facing camera (the back of the device).
    Back,
    /// USB / IP / desk camera that doesn't have a stable orientation
    /// relative to the device chassis.
    External,
}

/// One row in the registry. Carries enough capability metadata for
/// the calling module to populate `DeviceCapabilities` without
/// re-querying the platform.
#[derive(Clone, Debug, Deserialize)]
pub struct RegisteredVideoDevice {
    /// Stable id the embedder picked. Round-trips through
    /// `set_current_devices`; must remain unique within one
    /// registration. On Android this is typically the Camera2
    /// camera id ("0", "1", ...).
    pub id: String,
    /// Display name suitable for a settings dropdown.
    pub name: String,
    /// True for the device the platform recommended as the default
    /// (e.g. the back camera on a phone).
    #[serde(default)]
    pub is_default: bool,
    /// Supported `(width, height)` pairs in pixels. Empty = caller
    /// didn't enumerate; the UI should treat that as "unknown,
    /// negotiate at capture time".
    #[serde(default)]
    pub resolutions: Vec<(u32, u32)>,
    /// Supported frame rates in Hz. Same "empty = unknown" rule.
    #[serde(default)]
    pub frame_rates: Vec<u32>,
    /// Lens facing direction, when the platform tells us.
    #[serde(default)]
    pub facing: Option<VideoFacing>,
}

static VIDEO_INPUTS: OnceLock<RwLock<Vec<RegisteredVideoDevice>>> = OnceLock::new();

fn video_inputs_slot() -> &'static RwLock<Vec<RegisteredVideoDevice>> {
    VIDEO_INPUTS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Replace the registered video-input list. Called by the JNI bridge
/// after the embedder enumerates cameras; safe to call repeatedly
/// (e.g. on `onConfigurationChanged`).
pub fn set_video_inputs(devices: Vec<RegisteredVideoDevice>) {
    let mut slot = video_inputs_slot().write().expect("video inputs lock poisoned");
    *slot = devices;
}

/// Snapshot of the currently registered video inputs. Returns an
/// owned clone so the caller doesn't have to hold the lock across an
/// `await` or longer computation.
pub fn registered_video_inputs() -> Vec<RegisteredVideoDevice> {
    video_inputs_slot()
        .read()
        .expect("video inputs lock poisoned")
        .clone()
}

/// Empty the registry. Mainly useful for tests; production code
/// should call [`set_video_inputs`] with a fresh list instead.
pub fn clear_video_inputs() {
    let mut slot = video_inputs_slot().write().expect("video inputs lock poisoned");
    slot.clear();
}

/// Parse a JSON array of registered video devices. Used by the JNI
/// bridge so the wire format stays self-describing and the Kotlin
/// side doesn't have to learn a Rust struct layout.
pub fn parse_video_inputs_json(json: &str) -> Result<Vec<RegisteredVideoDevice>, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_round_trip() {
        clear_video_inputs();
        assert!(registered_video_inputs().is_empty());

        let devices = vec![
            RegisteredVideoDevice {
                id: "0".to_string(),
                name: "Back Camera".to_string(),
                is_default: true,
                resolutions: vec![(1920, 1080), (1280, 720)],
                frame_rates: vec![30, 60],
                facing: Some(VideoFacing::Back),
            },
            RegisteredVideoDevice {
                id: "1".to_string(),
                name: "Front Camera".to_string(),
                is_default: false,
                resolutions: vec![(1280, 720)],
                frame_rates: vec![30],
                facing: Some(VideoFacing::Front),
            },
        ];

        set_video_inputs(devices.clone());
        let snap = registered_video_inputs();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].id, "0");
        assert!(snap[0].is_default);
        assert_eq!(snap[1].facing, Some(VideoFacing::Front));

        clear_video_inputs();
        assert!(registered_video_inputs().is_empty());
    }

    #[test]
    fn parses_json_payload() {
        let json = r#"[
            {
                "id": "0",
                "name": "Back",
                "is_default": true,
                "resolutions": [[1280, 720]],
                "frame_rates": [30],
                "facing": "back"
            }
        ]"#;
        let parsed = parse_video_inputs_json(json).expect("valid json");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "Back");
        assert_eq!(parsed[0].facing, Some(VideoFacing::Back));
    }

    #[test]
    fn parses_minimal_payload() {
        // is_default, resolutions, frame_rates and facing all default.
        let json = r#"[{"id": "x", "name": "Some camera"}]"#;
        let parsed = parse_video_inputs_json(json).expect("valid json");
        assert_eq!(parsed.len(), 1);
        assert!(!parsed[0].is_default);
        assert!(parsed[0].resolutions.is_empty());
        assert!(parsed[0].facing.is_none());
    }
}
