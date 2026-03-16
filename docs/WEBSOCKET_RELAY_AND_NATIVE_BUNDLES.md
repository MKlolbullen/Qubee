# WebSocket relay + native bundle wiring

This step replaces the shell-only relay path with a real protocol shape:

- Android now targets a WebSocket relay by default: `ws://10.0.2.2:8787/ws`
- Relay auth uses a challenge/response flow
- The JNI contract now expects serialized identity bundles instead of random placeholder bytes
- Session creation now expects a structured peer public bundle

## Android side

### Relay transport

The active relay transport is selected in `QubeeServiceLocator`.

- `WebSocketRelayTransport` is used when `BuildConfig.DEFAULT_RELAY_URL` starts with `ws` or `wss`
- `DemoRelayTransport` remains as an escape hatch for local shell mode

### Identity persistence

`IdentityEntity` now stores:

- `publicBundleBase64`
- `identityBundleBase64`
- `relayHandle`
- `deviceId`

That gives the app enough state to:

- reconnect to the relay after restart
- restore the native identity bundle into Rust
- sign relay challenges via JNI

### Relay auth flow

1. App creates or restores an identity bundle.
2. App opens a WebSocket to the relay.
3. App sends `hello` with relay handle, device id, display name and public bundle.
4. Relay sends a challenge.
5. App signs `relaySessionId:challenge` using the Rust identity bundle.
6. Relay verifies the signature against the advertised public bundle.
7. Relay marks the socket authenticated and starts routing envelopes.

## Rust side

The JNI layer is intentionally being pulled away from the previous placeholder behavior.

The new contract expects:

- `nativeGenerateIdentityBundle(...) -> byte[]`
- `nativeRestoreIdentityBundle(bundle) -> boolean`
- `nativeSignRelayChallenge(bundle, challenge) -> byte[]`
- `nativeCreateRatchetSession(contactId, peerPublicBundle, isInitiator) -> byte[]`
- `nativeEncryptMessage(sessionId, plaintext) -> byte[]`
- `nativeDecryptMessage(sessionId, ciphertext) -> byte[]`

The payloads are now JSON bundle bytes rather than opaque fake blobs.

## Relay server

A reference relay server is added as a Rust binary:

- `src/bin/qubee_relay_server.rs`

It provides:

- WebSocket accept loop
- challenge/response authentication
- in-memory routing by relay handle
- delivery acknowledgements
- peer bundle lookup
- basic in-memory offline queueing

This is a dev relay, not production infrastructure.

## Important caveat

The Android shell can still run without the native library, but real relay authentication requires the native library to be present and the Rust identity bundle to be restorable.

That is deliberate. Fake transport auth is worse than no transport auth. Cryptographic cosplay belongs in museums, not messengers.
