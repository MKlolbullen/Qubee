# Qubee: Room + Relay + Crypto wiring

This revision moves the Android shell past the purely in-memory stage.

## What changed

- Added **Room** persistence for:
  - identity
  - conversations
  - sessions
  - messages
- Added a **relay transport seam** (`RelayTransport`) with a demo implementation (`DemoRelayTransport`)
- Added a **crypto engine** (`RelayCryptoEngine`) that:
  - attempts JNI / Rust first
  - falls back to app-managed AES-GCM when native functions are unavailable or incomplete
- Replaced the in-memory app flow with a repository-backed flow built on `Flow` + `Room`

## Important caveat

The Rust side is still not fully trustworthy as a production dependency in this repo. The Android shell now **reaches for** native identity/session/encryption functions, but the shell still contains a safe fallback because the Rust crate remains structurally inconsistent.

That means the new Android app is **better wired**, but not yet cryptographically production-ready.

## New core files

- `app/src/main/appshell/java/com/qubee/messenger/data/MessengerRepository.kt`
- `app/src/main/appshell/java/com/qubee/messenger/data/QubeeServiceLocator.kt`
- `app/src/main/appshell/java/com/qubee/messenger/data/db/*`
- `app/src/main/appshell/java/com/qubee/messenger/transport/*`
- `app/src/main/appshell/java/com/qubee/messenger/crypto/RelayCryptoEngine.kt`

## Message flow

1. Create/load identity
2. Ensure a session exists for the conversation
3. Encrypt the message
4. Persist it locally in Room with a delivery state
5. Publish envelope through relay transport
6. Receive receipt / incoming envelope
7. Decrypt incoming envelope
8. Persist decrypted message in Room
9. UI observes Room-backed flows and updates

## Next real step

Swap `DemoRelayTransport` with a real authenticated websocket relay and make the Rust JNI side emit **real serialized identity/session bundles** instead of placeholder bytes.
