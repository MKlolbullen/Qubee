#![no_main]
//! Fuzz the 1:1 `QUBEE_DMS` decoder and the sender-inspection helper.
use libfuzzer_sys::fuzz_target;
use qubee_crypto::ratchet::direct::inspect_direct_sender;
use qubee_crypto::ratchet::direct_message::DirectMessage;

fuzz_target!(|data: &[u8]| {
    let _ = DirectMessage::from_wire(data);
    let _ = inspect_direct_sender(data);
});
