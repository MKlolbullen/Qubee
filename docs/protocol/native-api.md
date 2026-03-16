# Native API Contract

The JNI surface must remain intentionally small.

## Approved operations

- `initialize()`
- `restoreIdentity(encryptedBlob)`
- `createIdentity(displayName)`
- `exportInviteBundle()`
- `inspectInviteBundle(payload)`
- `createSession(peerBundle)`
- `encryptMessage(sessionId, plaintext)`
- `decryptMessage(sessionId, envelope)`
- `computeSafetyCode(peerBundle)`
- `wipeNativeState()`

## Contract rules

- every function must have a documented input and output schema
- all returned objects must be versioned
- opaque blobs must not be passed without a documented encoding
- native wipe must be callable independently of normal app shutdown
