# Qubee QR + Relay Resilience Pass

This pass moves the mobile shell from “payload text and hopeful delivery semantics” toward a more believable secure messenger foundation.

## What changed

### 1. Actual QR invite rendering and scanning

The invite screen now:
- renders the exported invite payload as a real QR code using ZXing core
- supports QR scanning using `zxing-android-embedded`
- still keeps manual payload import for desktop/debug flows

Relevant files:
- `app/src/main/appshell/java/com/qubee/messenger/ui/screens/InviteScreen.kt`
- `app/src/main/appshell/java/com/qubee/messenger/ui/qr/QrBitmapGenerator.kt`
- `app/src/main/appshell/java/com/qubee/messenger/ui/qr/QrScanActivity.kt`
- `app/src/main/appshell/AndroidManifest.xml`

### 2. Better trust UX

The chat header now makes trust state explicit:
- verified vs unverified contact state
- visible safety code
- guidance to verify before trusting

Relevant file:
- `app/src/main/appshell/java/com/qubee/messenger/ui/screens/ChatScreen.kt`

### 3. Persistent outbound replay after reconnect

Local outbound messages are now persisted and replayed after relay authentication returns.

Flow:
1. message inserted locally
2. websocket publish attempted
3. delivery state becomes `Sent` or `Failed`
4. on relay re-authentication, pending outbound messages are replayed
5. relay delivery ack updates the message to `Delivered`

Relevant files:
- `app/src/main/appshell/java/com/qubee/messenger/data/MessengerRepository.kt`
- `app/src/main/appshell/java/com/qubee/messenger/data/db/QubeeDao.kt`
- `app/src/main/appshell/java/com/qubee/messenger/transport/WebSocketRelayTransport.kt`

### 4. Server-side duplicate suppression for replayed messages

The reference relay now tracks delivered message IDs to avoid duplicate delivery when a client resends a message after reconnect.

Relevant file:
- `src/bin/qubee_relay_server.rs`

### 5. Background sync scaffold

This is **not** full push messaging yet.

Instead, the Android app now includes a pragmatic WorkManager-based background sync scaffold that:
- re-initializes the repository when network is available
- replays pending outbound messages
- prepares the app for future push wakeup integration

Relevant file:
- `app/src/main/appshell/java/com/qubee/messenger/background/RelaySyncWorker.kt`

## What this is not yet

This is not yet:
- a full camera-permission polished UX
- FCM/APNs push wakeup integration
- end-to-end tested Android production messaging
- full offline inbound sync state reconciliation

## Next logical step

The next sane step is:
- add explicit contact verification screen / trust details screen
- add proper inbound sync cursor / message history fetch on reconnect
- add FCM-backed wakeup or relay push adapter
- harden native session serialization so session rehydration survives process death cleanly
