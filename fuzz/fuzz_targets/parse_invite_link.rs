#![no_main]
//! Fuzz the `qubee://invite/...` deep-link parser with arbitrary UTF-8.
use libfuzzer_sys::fuzz_target;
use qubee_crypto::groups::group_invite::InvitePayload;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = InvitePayload::from_invite_link(s);
    }
});
