# Unlock + WebRTC Transition Pass

This pass wires the keystore/SQLCipher seam into the actual app lifecycle and starts moving live delivery away from relay-first semantics.

## What changed

### Unlock and onboarding
- The app no longer initializes the repository and encrypted database at process start.
- `MainActivity` now requests biometric/device-credential auth with `BiometricPrompt`.
- Only after successful authentication does `QubeeServiceLocator.unlockRepository()`:
  - warm up the keystore AES key
  - decrypt or create the SQLCipher passphrase envelope
  - open the Room + SQLCipher database
  - bind the repository
- The UI now has a dedicated `UnlockScreen` before onboarding or conversations.

### WebRTC transition
- Added `WebRtcEnvelopeTransport` as a real `RTCDataChannel` seam.
- Added `HybridEnvelopeDispatcher` that prefers WebRTC for live envelopes and falls back to relay when no data channel is open.
- `MessengerRepository.sendMessage()` and `replayPendingOutbound()` now use the hybrid dispatcher instead of blindly publishing to relay first.
- `ensureConversationSession()` starts peer bootstrap so session establishment can begin nudging the app toward WebRTC.

## Honest limitations
- This is still not a fully working SDP/ICE implementation.
- Signaling bootstrap remains incomplete and relay is still required for recovery/history plus as a fallback.
- The WebRTC seam is real, but the app is not yet a verified zero-server messenger.

## Next step
- Implement actual SDP offer/answer + ICE candidate exchange over the selected bootstrap transport(s)
- Persist peer WebRTC session metadata
- Route receipts and read cursors over RTCDataChannel when available
