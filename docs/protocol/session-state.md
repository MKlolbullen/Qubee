# Session State Format

Session state is the local persisted record that lets the client resume encrypted messaging and trust decisions after restart.

## Goals

- track the active session identity
- support replay prevention and counter continuity
- support explicit invalidation when trust changes

## Canonical fields

- `sessionId`
- `conversationId`
- `peerHandle`
- `peerFingerprint`
- `localDeviceId`
- `nativeBacked`
- `stateLabel`
- `lastUsedAt`
- `messageCount`
- `invalidatedAt`

## Rules

- state must be invalidated on verified key change
- state must not silently migrate across peer fingerprint changes
- counters must only move forward
- UI may describe the session, but the persisted record is the source of truth
