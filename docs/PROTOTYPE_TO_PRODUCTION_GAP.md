# Prototype to Production Gap

## Current strengths
- coherent Compose shell
- JNI seam already exists
- Room persistence and reconnect logic already modeled
- invite QR / trust / key-change UX already present

## Current lies we should stop telling ourselves
- relay transport is not zero-server messaging
- plain Room is not enough for hostile-device assumptions
- “native” does not automatically mean secure if secrets are serialized too freely
- NAT traversal is not solved by putting “WebRTC” in a README and squinting with confidence

## Hardening priorities

### 1. Local secrets
- Keystore-backed AES key with user-auth requirement
- encrypted SQLCipher passphrase envelope
- wipe path for kill-switch / logout / key reset

### 2. Native core discipline
- minimize what leaves Rust in serialized form
- add explicit zeroization entrypoints
- document session state transitions and ratchet assumptions

### 3. Transport honesty
- keep relay for development, testing, and fallback bootstrap
- add WebRTC data-channel as the real peer transport target
- add local bootstrap for nearby onboarding
- add onion/WAN bootstrap only after protocol and lifecycle are clear

### 4. UI honesty
- show when the app is in relay-backed mode
- show whether secure local storage is actually active
- surface kill-switch and trust reset meaningfully
