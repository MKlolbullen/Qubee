use rand::rngs::OsRng;
use rand::RngCore;

pub fn generate_oob_secret() -> Vec<u8> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret.to_vec()
}
