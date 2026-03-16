use rand::rngs::OsRng;
use rand::RngCore;

pub fn generate_sas_code() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    let code = u32::from_be_bytes(bytes);
    format!("{:08}", code % 100_000_000)
}
