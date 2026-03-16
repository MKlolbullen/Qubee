# Trust Reset + Multi-Device Receipts and Unread Reconciliation

This pass makes Qubee behave less like a single-device prototype and more like a messenger that expects real-world mess.

## What changed

### 1. Key change detection resets trust
- `ConversationEntity` now stores:
  - `trustResetRequired`
  - `previousPeerFingerprint`
  - `lastKeyChangeAt`
- When a new peer bundle arrives and the fingerprint changes, the client:
  - invalidates the existing session
  - marks the conversation unverified
  - records the previous fingerprint
  - surfaces the change in chat + trust details UI

### 2. Device-aware receipts
- `MessageEntity` now stores:
  - `originDeviceId`
  - delivered-device count + device set
  - read-device count + device set
  - `lastReceiptAt`
- Outbound messages now show aggregated delivery/read state from multiple recipient devices.

### 3. Read cursor sync across sibling devices
- When a device reads a conversation, it publishes a `read_cursor` frame.
- The relay can fan this out to:
  - sibling devices on the same account for unread reconciliation
  - sender devices so outbound messages can be marked read
- Conversations now track `lastReadCursorAt`.

### 4. History reconciliation now includes more than messages
- `history_sync_response` now carries:
  - envelopes
  - contact requests
  - receipts
  - read cursors

## Android changes
- `MessengerRepository` now handles:
  - trust reset on key change
  - read cursor publication on `clearUnread`
  - device-aware receipt merging
  - read reconciliation from remote and sibling devices
- `TrustDetailsScreen` now shows explicit key continuity warnings.
- `ChatScreen` and `ConversationCard` surface trust-reset and multi-device state.

## Relay expectations
The relay should maintain per-handle device connections and be able to replay receipts/read cursors during history sync. The included Rust relay protocol was extended accordingly, but treat it as a reference implementation, not a production relay.

## Caveat
This pass is structurally serious, but it was not compiled in this environment. No Android SDK and no cargo toolchain were available here.
