# Trust details + inbound history reconciliation

This pass adds two reliability/security layers that a real messenger needs:

1. **Trust details screen**
   - Shows local fingerprint, peer fingerprint, safety code, session information, pending outbound count, and last successful history reconciliation time.
   - Lets the user mark the contact as verified from a dedicated security view instead of burying trust state in chat chrome.

2. **Inbound history reconciliation on reconnect**
   - After relay authentication, the Android client requests relay history since the locally stored sync cursor.
   - The relay responds with envelopes and contact requests newer than that cursor.
   - The client deduplicates inbound messages by `messageId` and contact requests by `requestId`.
   - The sync cursor is persisted in Room (`sync_state`) and advanced as inbound history is processed.

## Android pieces

- `MessengerRepository.trustDetailsFlow(...)`
- `TrustDetailsScreen.kt`
- `SyncStateEntity.kt`
- `RelayProtocol.kt` / `WebSocketRelayTransport.kt`
- `RelaySyncWorker.kt`

## Relay pieces

- `RelayFrame::HistorySyncRequest`
- `RelayFrame::HistorySyncResponse`
- `qubee_relay_server.rs` now stores per-recipient history and returns deltas after reconnect.

## Important caveat

This is a pragmatic reconciliation layer, not a final production sync design. It is enough to make reconnect far less flaky and to stop losing inbound state whenever the socket sneezes, but a production version should eventually move to:

- explicit server-side per-device cursors or receipts
- bounded history retention / compaction
- authenticated multi-device fanout semantics
- attachment/event timeline sync
- better unread state reconciliation across devices
