use crate::relay_security::RelayPublicBundleEntry;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEnvelope {
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "senderHandle")]
    pub sender_handle: String,
    #[serde(rename = "recipientHandle")]
    pub recipient_handle: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "ciphertextBase64")]
    pub ciphertext_base64: String,
    pub algorithm: String,
    #[serde(rename = "sentAt")]
    pub sent_at: u64,
    #[serde(rename = "senderDeviceId", default)]
    pub sender_device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayContactRequest {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "senderHandle")]
    pub sender_handle: String,
    #[serde(rename = "recipientHandle")]
    pub recipient_handle: String,
    #[serde(rename = "senderDisplayName")]
    pub sender_display_name: String,
    #[serde(rename = "publicBundleBase64")]
    pub public_bundle_base64: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "sentAt")]
    pub sent_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReceipt {
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "senderHandle")]
    pub sender_handle: String,
    #[serde(rename = "recipientHandle")]
    pub recipient_handle: String,
    #[serde(rename = "recipientDeviceId")]
    pub recipient_device_id: String,
    #[serde(rename = "receiptType")]
    pub receipt_type: String,
    #[serde(rename = "recordedAt")]
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReadCursor {
    #[serde(rename = "cursorId")]
    pub cursor_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    pub handle: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "readThroughTimestamp")]
    pub read_through_timestamp: u64,
    #[serde(rename = "recordedAt")]
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayFrame {
    #[serde(rename = "hello")]
    Hello {
        handle: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "displayName")]
        display_name: String,
        #[serde(rename = "publicBundleBase64")]
        public_bundle_base64: String,
        #[serde(rename = "identityFingerprint")]
        identity_fingerprint: String,
    },
    #[serde(rename = "challenge")]
    Challenge {
        #[serde(rename = "relaySessionId")]
        relay_session_id: String,
        challenge: String,
    },
    #[serde(rename = "authenticate")]
    Authenticate {
        handle: String,
        #[serde(rename = "relaySessionId")]
        relay_session_id: String,
        challenge: String,
        #[serde(rename = "publicBundleBase64")]
        public_bundle_base64: String,
        #[serde(rename = "identityFingerprint")]
        identity_fingerprint: String,
        #[serde(rename = "signatureBase64")]
        signature_base64: String,
    },
    #[serde(rename = "authenticated")]
    Authenticated {
        #[serde(rename = "relaySessionId")]
        relay_session_id: String,
        handle: String,
    },
    #[serde(rename = "binding_conflict")]
    BindingConflict {
        handle: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "existingIdentityFingerprint")]
        existing_identity_fingerprint: String,
        #[serde(rename = "requestedIdentityFingerprint")]
        requested_identity_fingerprint: String,
        #[serde(rename = "relinkToken")]
        relink_token: String,
        message: String,
    },
    #[serde(rename = "key_rotation_request")]
    KeyRotationRequest {
        handle: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "currentIdentityFingerprint")]
        current_identity_fingerprint: String,
        #[serde(rename = "newPublicBundleBase64")]
        new_public_bundle_base64: String,
        #[serde(rename = "newIdentityFingerprint")]
        new_identity_fingerprint: String,
    },
    #[serde(rename = "key_rotation_applied")]
    KeyRotationApplied {
        handle: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "oldIdentityFingerprint")]
        old_identity_fingerprint: String,
        #[serde(rename = "newIdentityFingerprint")]
        new_identity_fingerprint: String,
        #[serde(rename = "rotatedAt")]
        rotated_at: u64,
    },
    #[serde(rename = "approve_device_relink")]
    ApproveDeviceRelink {
        handle: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "relinkToken")]
        relink_token: String,
    },
    #[serde(rename = "device_relink_applied")]
    DeviceRelinkApplied {
        handle: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "oldIdentityFingerprint")]
        old_identity_fingerprint: String,
        #[serde(rename = "newIdentityFingerprint")]
        new_identity_fingerprint: String,
        #[serde(rename = "relinkToken")]
        relink_token: String,
        #[serde(rename = "relinkedAt")]
        relinked_at: u64,
    },
    #[serde(rename = "publish")]
    Publish { envelope: RelayEnvelope },
    #[serde(rename = "envelope")]
    Envelope { envelope: RelayEnvelope },
    #[serde(rename = "contact_request")]
    ContactRequest { request: RelayContactRequest },
    #[serde(rename = "receipt")]
    Receipt { receipt: RelayReceipt },
    #[serde(rename = "read_cursor")]
    ReadCursor { cursor: RelayReadCursor },
    #[serde(rename = "delivery_ack")]
    DeliveryAck {
        #[serde(rename = "messageId")]
        message_id: String,
        #[serde(rename = "deliveredAt")]
        delivered_at: u64,
    },
    #[serde(rename = "peer_bundle_request")]
    PeerBundleRequest {
        #[serde(rename = "peerHandle")]
        peer_handle: String,
        #[serde(rename = "deviceId", default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    #[serde(rename = "peer_bundle_response")]
    PeerBundleResponse {
        #[serde(rename = "peerHandle")]
        peer_handle: String,
        #[serde(rename = "publicBundleBase64")]
        public_bundle_base64: Option<String>,
        #[serde(default)]
        bundles: Vec<RelayPublicBundleEntry>,
    },
    #[serde(rename = "history_sync_request")]
    HistorySyncRequest { since: u64 },
    #[serde(rename = "history_sync_response")]
    HistorySyncResponse {
        #[serde(rename = "relaySessionId")]
        relay_session_id: String,
        #[serde(rename = "syncedUntil")]
        synced_until: u64,
        envelopes: Vec<RelayEnvelope>,
        #[serde(rename = "contactRequests")]
        contact_requests: Vec<RelayContactRequest>,
        receipts: Vec<RelayReceipt>,
        #[serde(rename = "readCursors")]
        read_cursors: Vec<RelayReadCursor>,
    },
    /// WebRTC signaling frame — relayed to the target handle for P2P bootstrap.
    #[serde(rename = "signaling")]
    Signaling {
        #[serde(rename = "fromHandle")]
        from_handle: String,
        #[serde(rename = "toHandle")]
        to_handle: String,
        #[serde(rename = "signalType")]
        signal_type: String,
        payload: String,
        #[serde(rename = "sentAt")]
        sent_at: u64,
    },
    #[serde(rename = "error")]
    Error { message: String },
}
