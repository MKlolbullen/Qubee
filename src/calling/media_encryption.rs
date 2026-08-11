//! Media stream encryption utilities.
//!
//! This module provides a simple abstraction over symmetric encryption for
//! protecting audio and video frames during real‑time calls.  The functions
//! defined here derive per‑stream keys from a single [`MediaKey`] using
//! HKDF and then apply the ChaCha20‑Poly1305 AEAD cipher to each frame.
//!
//! The design keeps encryption orthogonal to the WebRTC transport layer – it
//! assumes the caller already has an agreed [`MediaKey`] (e.g., derived from
//! the double ratchet) and that frame boundaries are preserved by the caller.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

use crate::security::secure_rng;

/// Opaque wrapper around a 32‑byte media key used for deriving stream keys.
///
/// The contents are kept in a [`SecretBox`] to ensure they are cleared
/// from memory on drop. Deliberately not `Clone`: each holder that
/// needs its own copy calls [`MediaKey::duplicate`], so key copies are
/// explicit in the source.
pub struct MediaKey(SecretBox<[u8; 32]>);

impl MediaKey {
    /// Creates a new `MediaKey` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Explicit copy for handing the key to another owner (e.g. the
    /// peer-connection layer).
    pub fn duplicate(&self) -> Self {
        Self::new(*self.0.expose_secret())
    }

    /// Returns the raw key material.  This should be used sparingly since it
    /// exposes the secret in memory.
    fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// Root media-key manager, one per [`CallManager`]: derives an
/// independent [`MediaKey`] for every `(call, participant)` pair from a
/// random per-process root. Interim design — the root will be replaced
/// by ratchet-derived material when signaling rides the 1:1 sessions,
/// at which point this becomes a thin KDF over that shared secret.
pub struct MediaEncryption {
    root: SecretBox<[u8; 32]>,
}

const MEDIA_KEY_KDF_INFO: &[u8] = b"qubee media key v1";

impl MediaEncryption {
    /// Create a manager with a fresh random root.
    pub fn new() -> Result<Self> {
        let root = secure_rng::random::array::<32>()?;
        Ok(Self {
            root: SecretBox::new(Box::new(root)),
        })
    }

    /// Derive the media key for one participant in one call. Same
    /// inputs give the same key (a reconnect re-derives it); distinct
    /// calls or participants never share one.
    pub fn generate_media_key(&self, call_id: &[u8], participant: &[u8]) -> MediaKey {
        let hk = Hkdf::<Sha256>::new(None, self.root.expose_secret());
        let mut info =
            Vec::with_capacity(MEDIA_KEY_KDF_INFO.len() + call_id.len() + participant.len());
        info.extend_from_slice(MEDIA_KEY_KDF_INFO);
        info.extend_from_slice(call_id);
        info.extend_from_slice(participant);
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("HKDF expand failed");
        MediaKey::new(okm)
    }
}

impl MediaKey {
    /// Derive a per‑stream key using HKDF.  The `stream_id` should be unique
    /// per logical media stream (for example, `0` for audio and `1` for
    /// video).  Reusing a `stream_id` with the same `media_key` will produce
    /// the same derived key.
    fn derive_stream_key(&self, stream_id: u64) -> Key {
        let hk = Hkdf::<Sha256>::new(None, self.as_bytes());
        let mut okm = [0u8; 32];
        let info = stream_id.to_le_bytes();
        hk.expand(&info, &mut okm).expect("HKDF expand failed");
        *Key::from_slice(&okm)
    }

    /// Encrypt a media frame using the derived stream key.  The `stream_id`
    /// identifies which derived key to use.  A random 96‑bit nonce is
    /// generated for each frame and prepended to the ciphertext output.
    pub fn encrypt_frame(&self, stream_id: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.derive_stream_key(stream_id);
        let cipher = ChaCha20Poly1305::new(&key);
        // Generate a random 12‑byte nonce.
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .context("media frame encryption failed")?;
        // Prepend nonce to ciphertext.
        let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a media frame.  Expects the first 12 bytes of `data` to be
    /// the random nonce used during encryption.  Returns the plaintext on
    /// success.
    pub fn decrypt_frame(&self, stream_id: u64, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow::anyhow!("ciphertext too short"));
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let key = self.derive_stream_key(stream_id);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .context("media frame decryption failed")?;
        Ok(plaintext)
    }
}

/// Convenience wrapper binding a [`MediaKey`] to a specific
/// `stream_id`, for callers that encrypt/decrypt many frames on one
/// stream without repeatedly passing the id.
pub struct StreamEncryption<'a> {
    inner: &'a MediaKey,
    stream_id: u64,
}

impl<'a> StreamEncryption<'a> {
    /// Create a new stream encryption context for the given `stream_id`.
    pub fn new(inner: &'a MediaKey, stream_id: u64) -> Self {
        Self { inner, stream_id }
    }

    /// Encrypt a frame on this stream.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt_frame(self.stream_id, plaintext)
    }

    /// Decrypt a frame on this stream.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt_frame(self.stream_id, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_per_stream() {
        let root = MediaEncryption::new().unwrap();
        let key = root.generate_media_key(&[1u8; 16], &[2u8; 32]);
        let frame = key.encrypt_frame(0, b"voice frame").unwrap();
        assert_eq!(key.decrypt_frame(0, &frame).unwrap(), b"voice frame");
        // A different stream id derives a different key: the audio
        // frame must not open on the video stream.
        assert!(key.decrypt_frame(1, &frame).is_err());
    }

    #[test]
    fn keys_are_isolated_per_call_and_participant() {
        let root = MediaEncryption::new().unwrap();
        let k_a = root.generate_media_key(&[1u8; 16], &[2u8; 32]);
        let k_b = root.generate_media_key(&[1u8; 16], &[3u8; 32]);
        let k_c = root.generate_media_key(&[9u8; 16], &[2u8; 32]);
        let frame = k_a.encrypt_frame(0, b"only for a").unwrap();
        assert!(k_b.decrypt_frame(0, &frame).is_err());
        assert!(k_c.decrypt_frame(0, &frame).is_err());
        // Same inputs re-derive the same key (reconnect path).
        let k_a2 = root.generate_media_key(&[1u8; 16], &[2u8; 32]);
        assert_eq!(k_a2.decrypt_frame(0, &frame).unwrap(), b"only for a");
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let root = MediaEncryption::new().unwrap();
        let key = root.generate_media_key(&[1u8; 16], &[2u8; 32]);
        let mut frame = key.encrypt_frame(0, b"tamper me").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert!(key.decrypt_frame(0, &frame).is_err());
        assert!(key.decrypt_frame(0, &frame[..11]).is_err(), "short input");
    }

    #[test]
    fn duplicate_holds_the_same_key() {
        let root = MediaEncryption::new().unwrap();
        let key = root.generate_media_key(&[1u8; 16], &[2u8; 32]);
        let copy = key.duplicate();
        let frame = StreamEncryption::new(&key, 7)
            .encrypt(b"via stream")
            .unwrap();
        assert_eq!(
            StreamEncryption::new(&copy, 7).decrypt(&frame).unwrap(),
            b"via stream"
        );
    }
}
