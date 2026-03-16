# Message Envelope Format

Message envelopes are the versioned encrypted payload containers that travel over RTC or relay paths.

## Goals

- carry ciphertext, routing metadata, and replay-resistant identifiers
- remain transport-agnostic
- support receipts and read-state correlation

## Canonical fields

```json
{
  "version": 1,
  "messageId": "uuid",
  "conversationId": "stable-conversation-id",
  "senderHandle": "alice-qb-123",
  "originDeviceId": "pixel-8-primary",
  "timestamp": 1730000000000,
  "ciphertextBase64": "...",
  "sessionId": "session-uuid",
  "contentType": "text/plain"
}
```

## Rules

- `messageId` must be globally unique for dedupe and reconciliation
- `conversationId` must be deterministic for both peers
- `originDeviceId` must be present for multi-device receipts and read cursors
- ciphertext is opaque to the transport layer
- receipts and read cursors must reference the original `messageId` or stable conversation cursor
