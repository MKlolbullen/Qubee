# Zero-Server Bootstrap Notes

This repository currently contains an authenticated relay because it is the least-delusional way to iterate on message state, trust UX, and sync semantics.

A production “zero-server” Qubee should treat the relay as one of these only:
- temporary development transport
- optional bootstrap fallback
- optional rendezvous helper, never a plaintext message carrier

## Target layers

### Local bootstrap
Use a proximity mechanism to exchange signaling data:
- Wi‑Fi Direct for higher throughput when available
- BLE for low-bandwidth onboarding and fallback
- QR only as the initial static identity/public bundle bootstrap

### WAN bootstrap
Use onion-addressable or equivalent privacy-preserving rendezvous channels for SDP/ICE exchange.

### Transport
After signaling, messages should move over:
- WebRTC data channel
- ordered and reliable mode
- application payload already end-to-end encrypted before entering the transport

## Practical recommendation
Do not remove the relay until:
1. history reconciliation works over peer transport,
2. unread/receipt sync still works across reconnects,
3. Android background limits are handled with a foreground service and explicit user-visible policy.
