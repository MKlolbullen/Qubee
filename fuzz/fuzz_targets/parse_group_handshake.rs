#![no_main]
//! Fuzz the group-handshake wire decoder (the bounded-bincode path). Must
//! fail closed on any bytes — never panic, never over-allocate.
use libfuzzer_sys::fuzz_target;
use qubee_crypto::groups::group_handshake::GroupHandshake;

fuzz_target!(|data: &[u8]| {
    let _ = GroupHandshake::from_wire(data);
});
