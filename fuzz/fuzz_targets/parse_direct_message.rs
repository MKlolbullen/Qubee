#![no_main]
//! Fuzz the 1:1 `QUBEE_DMS` decoder and opaque-routing parser.
use libfuzzer_sys::fuzz_target;
use qubee_crypto::ratchet::direct_message::{inspect_direct_selectors, DirectMessage};

fuzz_target!(|data: &[u8]| {
    let _ = DirectMessage::from_wire(data);
    let _ = inspect_direct_selectors(data);
});
