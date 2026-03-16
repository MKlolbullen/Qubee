# Alpha Roadmap

This roadmap defines the shortest credible path from Qubee as a promising prototype to Qubee as a private alpha product.

## Product shape for alpha

Alpha is intentionally narrow:

- Android only
- 1:1 messaging only
- one primary device with linked-device groundwork
- QR and local bootstrap for contact establishment
- WebRTC data channel as the preferred live path
- relay-assisted signaling and recovery
- Android Keystore + SQLCipher + biometric unlock
- explicit trust reset on peer key changes
- offline queue and history reconciliation

Anything outside that scope is postponed unless it directly improves reliability of the alpha spine.

## Alpha spine

The alpha spine is the one end-to-end path that must become boringly reliable:

1. unlock app
2. open encrypted database
3. restore local identity
4. export or import contact invite
5. verify safety code
6. establish session
7. send encrypted message
8. receive decrypted message
9. show receipt and read state
10. recover after reconnect
11. detect key change
12. require re-verification or block
13. wipe local state when requested

## Milestones

### M1. Freeze protocol and boundary definitions

Deliverables:

- identity bundle format
- message envelope format
- session state format
- trust state machine
- device linking state machine
- frozen native API contract

Acceptance criteria:

- every message-bearing or trust-bearing object is versioned
- native JNI API surface is explicit and minimal
- trust transitions are documented and testable

### M2. Ship the alpha spine

Deliverables:

- unlock flow works against keystore-backed DB unlock
- invite export and import work
- safety-code verification works
- session establishment works
- send and receive work over live path and fallback path
- reconnect reconciliation restores missed data
- key changes reset trust and invalidate active session

Acceptance criteria:

- the same conversation can survive app restart, process death, and temporary network loss
- UI shows truthful state during recovery instead of optimistic fiction

### M3. Harden reliability and observability

Deliverables:

- transport diagnostics surface
- queue depth and retry visibility
- explicit failure reasons for bootstrap and peer connection
- automated tests for trust, reconciliation, serialization, and queue behavior

Acceptance criteria:

- developer can explain why a peer connection failed without guessing
- user can tell whether the app is connected, reconnecting, blocked, or falling back

## Priorities that stay out of scope for alpha

- groups
- calls
- desktop client
- iOS client
- embedded Tor daemon as a primary path
- custom post-quantum protocol experiments beyond the defined contract
- cosmetic features such as reactions, stickers, or media-rich chat surfaces

## Exit criteria for private alpha

Qubee is ready for a private alpha only when the alpha spine passes its checklist consistently on real devices and after repeated restart, reconnect, and key-change scenarios.
