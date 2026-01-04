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
use chacha20poly1305::{aead::{Aead, KeyInit, OsRng}, ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;

/// Opaque wrapper around a 32‑byte media key used for deriving stream keys.
///
/// The contents are kept in a [`Secret`] to ensure they are cleared from
/// memory on drop.
#[derive(Clone)]
pub struct MediaKey(Secret<[u8; 32]>);

impl MediaKey {
    /// Creates a new `MediaKey` from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Returns the raw key material.  This should be used sparingly since it
    /// exposes the secret in memory.
    fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// Context used to perform encryption/decryption of media frames.
///
/// A `MediaEncryption` instance derives a unique cipher key for each stream
/// based on a common [`MediaKey`] and a caller‑supplied `stream_id`.  It
/// maintains no internal state; callers are expected to supply a fresh
/// `stream_id` for each media stream (e.g., one for audio, one for video).
pub struct MediaEncryption {
    media_key: MediaKey,
}

impl MediaEncryption {
    /// Create a new `MediaEncryption` from the shared [`MediaKey`].
    pub fn new(media_key: MediaKey) -> Self {
        Self { media_key }
    }

    /// Derive a per‑stream key using HKDF.  The `stream_id` should be unique
    /// per logical media stream (for example, `0` for audio and `1` for
    /// video).  Reusing a `stream_id` with the same `media_key` will produce
    /// the same derived key.
    fn derive_stream_key(&self, stream_id: u64) -> Key<ChaCha20Poly1305> {
        let hk = Hkdf::<Sha256>::new(None, self.media_key.as_bytes());
        let mut okm = [0u8; 32];
        let info = stream_id.to_le_bytes();
        hk.expand(&info, &mut okm).expect("HKDF expand failed");
        Key::clone_from_slice(&okm)
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

/// Convenience type alias representing a stream‑level encryption context.
///
/// A `StreamEncryption` is simply a wrapper around a [`MediaEncryption`]
/// configured for a specific `stream_id`.  It captures the common case
/// where a caller wants to encrypt/decrypt multiple frames on a single
/// stream without repeatedly passing the `stream_id` parameter.
pub struct StreamEncryption<'a> {
    inner: &'a MediaEncryption,
    stream_id: u64,
}

impl<'a> StreamEncryption<'a> {
    /// Create a new stream encryption context for the given `stream_id`.
    pub fn new(inner: &'a MediaEncryption, stream_id: u64) -> Self {
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
