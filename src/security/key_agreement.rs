//! X25519 boundary shared by the authenticated handshake and DH ratchet.

use anyhow::{bail, Result};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Reject all-zero outputs before feeding a combiner/KDF. The contributory
/// check is constant-time. A drop guard clears early-return temporaries.
pub(crate) fn checked_x25519(
    secret: &StaticSecret,
    public: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        bail!("non-contributory X25519 key agreement");
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_and_nonzero_low_order_public_keys() {
        let secret = StaticSecret::from([9; 32]);
        let mut one = [0; 32];
        one[0] = 1;
        for bytes in [[0; 32], one] {
            assert!(checked_x25519(&secret, &PublicKey::from(bytes)).is_err());
        }
    }
}
