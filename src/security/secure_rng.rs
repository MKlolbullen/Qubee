//! Fallible operating-system randomness. No application PRNG state, clock,
//! filesystem scanning, timing measurements, or fallback entropy sources.
//! PQClean's C primitives have their own OS-randomness boundary; see the audit
//! notes in docs/security/crypto-boundary-hardening.md.

use anyhow::{Context, Result};
use zeroize::Zeroize;

fn fill_with(dest: &mut [u8], source: impl FnOnce(&mut [u8]) -> Result<()>) -> Result<()> {
    if dest.is_empty() {
        return Ok(());
    }
    if let Err(error) = source(dest) {
        // A failed OS request may have partially filled the destination.
        dest.zeroize();
        return Err(error);
    }
    Ok(())
}

fn fill_from_os(dest: &mut [u8]) -> Result<()> {
    fill_with(dest, |bytes| {
        getrandom::getrandom(bytes).context("operating-system randomness unavailable")
    })
}

/// Compatibility handle: every request goes directly to the OS CSPRNG.
pub struct SecureRng;

impl SecureRng {
    pub fn new() -> Result<Self> {
        let mut rng = Self;
        rng.reseed()?;
        Ok(rng)
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        fill_from_os(dest)
    }

    pub fn next_u64(&mut self) -> Result<u64> {
        random::u64()
    }

    pub fn next_u32(&mut self) -> Result<u32> {
        random::u32()
    }

    /// Availability check only. Reseeding is owned by the OS; there is no
    /// application seed or cached output to continue using on error.
    pub fn reseed(&mut self) -> Result<()> {
        let mut probe = zeroize::Zeroizing::new([0u8; 32]);
        fill_from_os(probe.as_mut())
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        // Stateless construction; requests remain fallible.
        Self
    }
}

/// Global facade whose initialization cannot panic on entropy failure.
pub struct GlobalSecureRng;

impl GlobalSecureRng {
    pub fn instance() -> &'static Self {
        static INSTANCE: GlobalSecureRng = GlobalSecureRng;
        &INSTANCE
    }

    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        fill_from_os(dest)
    }

    pub fn next_u64(&self) -> Result<u64> {
        random::u64()
    }

    pub fn reseed(&self) -> Result<()> {
        SecureRng.reseed()
    }
}

pub mod random {
    use super::*;

    pub fn bytes(len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        fill_from_os(&mut bytes)?;
        Ok(bytes)
    }

    pub fn array<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        fill_from_os(&mut bytes)?;
        Ok(bytes)
    }

    pub fn u64() -> Result<u64> {
        Ok(u64::from_le_bytes(array()?))
    }

    pub fn u32() -> Result<u32> {
        Ok(u32::from_le_bytes(array()?))
    }

    pub fn bool() -> Result<bool> {
        Ok(array::<1>()?[0] & 1 == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_entropy_failure_erases_output_and_propagates() {
        let mut dest = [0x55; 32];
        let result = fill_with(&mut dest, |bytes| {
            bytes[..16].fill(0xAA);
            anyhow::bail!("injected entropy failure")
        });
        assert!(result.is_err());
        assert_eq!(dest, [0; 32]);
    }

    #[test]
    fn request_after_failure_uses_a_fresh_source_call() {
        let mut dest = [0; 8];
        assert!(fill_with(&mut dest, |_| anyhow::bail!("unavailable")).is_err());
        fill_with(&mut dest, |bytes| {
            bytes.copy_from_slice(&42u64.to_le_bytes());
            Ok(())
        })
        .unwrap();
        assert_eq!(u64::from_le_bytes(dest), 42);
    }

    #[test]
    fn facade_supports_os_requests_and_empty_buffers() {
        let mut rng = SecureRng::new().unwrap();
        rng.fill_bytes(&mut []).unwrap();
        rng.next_u32().unwrap();
        GlobalSecureRng::instance().next_u64().unwrap();
        assert_eq!(random::bytes(24).unwrap().len(), 24);
        random::bool().unwrap();
    }
}
