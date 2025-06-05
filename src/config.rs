use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub enable_cover_traffic: bool,
    pub dummy_packet_frequency_secs: u64,
    pub trust_model: String, // "TOFU" or "pinned"
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            enable_cover_traffic: true,
            dummy_packet_frequency_secs: 15,
            trust_model: "TOFU".to_string(),
        }
    }
}
