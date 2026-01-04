use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum CallSignal {
    Offer { sdp: String, call_id: String },
    Answer { sdp: String, call_id: String },
    IceCandidate { candidate: String, sdp_mid: String, sdp_mline_index: u32, call_id: String },
    HangUp { call_id: String },
}

// Helper to wrap signaling inside your standard protocol
pub fn prepare_signal_message(signal: CallSignal) -> Vec<u8> {
    bincode::serialize(&signal).expect("Failed to serialize signal")
}
