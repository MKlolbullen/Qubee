use serde::{Serialize, Deserialize};

/// Represents a WebRTC signaling message wrapped for transport
/// over the secure Qubee chat channel.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CallSignal {
    Offer { 
        sdp: String, 
        call_id: String 
    },
    Answer { 
        sdp: String, 
        call_id: String 
    },
    IceCandidate { 
        candidate: String, 
        sdp_mid: String, 
        sdp_mline_index: u32, 
        call_id: String 
    },
    HangUp { 
        call_id: String 
    },
}

impl CallSignal {
    /// Serializes the signal to bytes for encryption
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Tries to parse bytes into a CallSignal
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
