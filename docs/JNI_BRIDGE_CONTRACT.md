# JNI bridge contract for Qubee

The Android shell now expects a **small and boring** native boundary. That is a compliment.

## Recommended exports

```text
nativeInitialize(): Boolean
nativeCreateIdentity(displayName: String): ByteArray?
nativeGetPublicBundle(): ByteArray?
nativeCreateSession(peerBundle: ByteArray): ByteArray?
nativeEncryptMessage(sessionId: String, plaintext: ByteArray): ByteArray?
nativeDecryptMessage(sessionId: String, ciphertext: ByteArray): ByteArray?
```

## Rules

- Return structured binary payloads or JSON bytes, not ad hoc blobs with hidden assumptions.
- Keep Android free of ratchet internals.
- Never make Kotlin reconstruct cryptographic state from vibes.
- Return explicit errors instead of panicking across JNI.

## Why smaller is better

The old JNI layer tried to expose too much while the native code still contained placeholder state. That creates the worst possible combo: a wide interface to unfinished internals.
