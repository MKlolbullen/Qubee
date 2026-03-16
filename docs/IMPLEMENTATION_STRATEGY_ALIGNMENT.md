# Qubee Implementation Strategy Alignment

This repository originally drifted between three states:
1. a conceptual README that overclaimed production properties,
2. a real but incomplete Android/Compose shell,
3. a Rust native core that is useful but not yet fully aligned with the “post-quantum zero-server” target.

This alignment pass does **not** pretend those three realities are the same thing.

## What this pass changes

### Keys and local secret handling
The implementation strategy requires Android Keystore to mediate sensitive material. This patch adds:
- `AppKeyManager.kt` for hardware-backed AES-GCM wrapping
- `DatabasePassphraseManager.kt` for storing a SQLCipher passphrase encrypted by the keystore key
- `KillSwitch.kt` for wiping the database, passphrase envelope, preferences, and JNI-side ephemeral state

### Database
The guide requires SQLCipher + Room. This patch adds:
- `SecureDatabaseFactory.kt` as the Room/SQLCipher construction seam
- explicit `Contact`, `Message`, and `SessionState` entities that match the guide, while leaving the existing shell entities intact

### Networking
The guide aims for WebRTC data-channel transport with decentralized bootstrap. This patch does **not** pretend the current relay already satisfies that. Instead it adds:
- `SignalingTransport.kt`
- `LocalBootstrapTransport.kt`
- `TorOnionBootstrapTransport.kt`
- `WebRtcSwarmCoordinator.kt`
- `P2pNodeService.kt`

These are scaffolds and interfaces for replacing relay-first transport with real peer bootstrap and WebRTC once the rest of the app is ready.

### GUI / UX
The prototype UI is already strong. The realistic next GUI move is not “more pretty pixels”, it is wiring security surfaces to real state:
- `FLAG_SECURE` on the main activity
- settings text aligned with actual storage/network strategy
- a place for kill-switch and secure-storage state to plug into the shell

## What remains hard

### “Zero server” is not a boolean switch
A messenger is not serverless just because the README wants it badly enough.

Hard parts still remaining:
- reliable NAT traversal on mobile networks
- background execution and reconnect behavior under Android Doze/app standby
- offline contact bootstrap and peer discovery
- safe multi-device identity semantics
- attachment storage and media lifecycle
- actual post-quantum session design instead of merely wrapping classical components with ambitious adjectives

## Recommended next build order

1. Finish Android Keystore + SQLCipher integration end-to-end.
2. Move the current relay to “bootstrap/fallback only” status in both docs and code.
3. Add WebRTC data-channel coordinator with local bootstrap first.
4. Add Tor/onion WAN bootstrap only after local flows are stable.
5. Replace remaining placeholder native session assumptions with an explicit protocol document.
