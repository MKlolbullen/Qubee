# SDP/ICE Exchange and RTC Control Path

This pass moves Qubee one layer closer to a real peer path instead of permanent relay gravity.

## What is now implemented

- Actual **SDP offer/answer** messages over the bootstrap signaling transports.
- Actual **ICE candidate** exchange over the same signaling channel.
- A `WebRtcEnvelopeTransport` that owns:
  - `PeerConnectionFactory`
  - per-peer `PeerConnection`
  - per-peer `RTCDataChannel`
- A `HybridEnvelopeDispatcher` that now sends:
  - encrypted message envelopes
  - delivery receipts
  - read cursors
  over RTC when the peer link is open, and falls back to relay when it is not.

## Why this matters

Before this pass, WebRTC was mostly a dignified placeholder. The app could *intend* to use a data channel, but the actual signaling dance that makes WebRTC real was missing.

Now the app can:

1. Create a peer connection.
2. Generate an SDP offer.
3. Send it over the bootstrap transports.
4. Receive an SDP answer.
5. Exchange ICE candidates.
6. Open a data channel.
7. Push envelopes, receipts, and read cursors over that live peer path.

## What is still not magically complete

Reality remains rude:

- `LocalBootstrapTransport` is still a scaffold, not a finished Wi-Fi Direct / BLE transport.
- `TorOnionBootstrapTransport` is still a scaffold, not a real onion rendezvous implementation.
- TURN is not implemented, so symmetric NAT hell can still ruin your afternoon.
- Relay remains necessary for:
  - fallback delivery
  - bootstrap while transport-specific layers are incomplete
  - history sync / offline reconciliation

## Practical behavior change

When a peer link is open:

- chat message envelopes prefer RTC
- delivery receipts prefer RTC
- read cursors prefer RTC

When the peer link is not open:

- the app bootstraps SDP/ICE
- then falls back to relay until the data channel is actually available

That is the honest hybrid model during transition.
