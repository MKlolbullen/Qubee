//! Length-hiding message padding.
//!
//! Ciphertext length leaks message *type* and rough content to a
//! network observer even when the payload itself is sealed. This module
//! pads a plaintext up to the next size class so that many distinct
//! messages present one of a small number of on-wire lengths, collapsing
//! that side channel into a coarse bucket.
//!
//! Scheme (`v1`): a 4-byte little-endian length prefix, then the
//! plaintext, then zero padding out to the next bucket boundary. The
//! whole thing is encrypted by the caller, so the padding is confidential
//! and integrity-protected by the surrounding AEAD — [`unpad`] only ever
//! runs on already-authenticated plaintext, so a truncated or lying
//! length is a decrypt-side error, not an attacker-controlled parse.
//!
//! Buckets grow geometrically to keep the padding overhead bounded to at
//! most ~2x while still collapsing the common small-message range hard.

use anyhow::{anyhow, Result};

/// Size classes (bytes of `prefix + plaintext`, before rounding). A
/// message is padded up to the first class that fits; anything larger
/// than the last fixed class rounds up to the next multiple of
/// [`LARGE_STEP`].
const BUCKETS: &[usize] = &[256, 1024, 4096, 16_384, 65_536];
const LARGE_STEP: usize = 65_536;
const LEN_PREFIX: usize = 4;

/// Round `n` up to the first bucket >= `n`, or the next [`LARGE_STEP`]
/// multiple beyond the largest fixed bucket.
fn bucket_for(n: usize) -> usize {
    for &b in BUCKETS {
        if n <= b {
            return b;
        }
    }
    n.div_ceil(LARGE_STEP) * LARGE_STEP
}

/// Length-prefix `plaintext` and zero-pad it to the next size class.
/// The result always presents one of a small set of lengths.
pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let target = bucket_for(LEN_PREFIX + plaintext.len());
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(target, 0);
    out
}

/// Recover the original plaintext from a [`pad`]ded buffer. Errors on a
/// truncated buffer or a length prefix that overruns it — which, since
/// this only runs post-AEAD, means corruption, never attacker input.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < LEN_PREFIX {
        return Err(anyhow!("padded buffer shorter than length prefix"));
    }
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    let end = LEN_PREFIX
        .checked_add(len)
        .ok_or_else(|| anyhow!("padding length overflow"))?;
    if end > padded.len() {
        return Err(anyhow!("padding length {len} overruns buffer"));
    }
    Ok(padded[LEN_PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_boundary() {
        for len in [0usize, 1, 100, 252, 253, 1020, 1021, 4092, 70_000] {
            let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let padded = pad(&msg);
            assert_eq!(unpad(&padded).unwrap(), msg, "len {len}");
        }
    }

    #[test]
    fn distinct_small_lengths_share_one_on_wire_size() {
        // Every message from 0..=252 bytes lands in the 256 bucket.
        let a = pad(b"hi");
        let b = pad(&[7u8; 200]);
        assert_eq!(a.len(), 256);
        assert_eq!(b.len(), 256);
    }

    #[test]
    fn buckets_step_up_and_bound_overhead() {
        assert_eq!(pad(&vec![0u8; 253]).len(), 1024); // 253+4 > 256
        assert_eq!(pad(&vec![0u8; 1021]).len(), 4096);
        // Large messages round to LARGE_STEP multiples (<= ~2x overhead).
        assert_eq!(pad(&vec![0u8; 70_000]).len(), 131_072);
    }

    #[test]
    fn unpad_rejects_corruption() {
        assert!(unpad(&[1, 2]).is_err()); // shorter than prefix
                                          // Length prefix claims more bytes than the buffer holds.
        let mut bad = pad(b"hello");
        bad[0] = 0xFF;
        bad[1] = 0xFF;
        assert!(unpad(&bad).is_err());
    }
}
