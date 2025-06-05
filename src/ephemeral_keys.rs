use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use anyhow::{Result, anyhow};

pub type EphemeralKeyStore = Arc<Mutex<HashMap<String, Vec<u8>>>>;

pub fn verify_and_pin_ephemeral_key(
    store: &EphemeralKeyStore,
    sender_id: &str,
    ephemeral_pk: &[u8]
) -> Result<()> {
    let mut pinned = store.lock().unwrap();

    if let Some(stored_key) = pinned.get(sender_id) {
        if stored_key != ephemeral_pk {
            return Err(anyhow!("Ephemeral key mismatch detected (possible MITM)"));
        }
    } else {
        pinned.insert(sender_id.to_string(), ephemeral_pk.to_vec());
    }

    Ok(())
}
