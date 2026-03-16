# Identity Bundle Format

Identity bundles are the versioned public contact objects exchanged during invite export, QR bootstrap, or local pairing.

## Goals

- allow another client to identify the peer
- provide enough material to start trust review and session establishment
- remain stable enough to parse across client versions

## Canonical fields

```json
{
  "version": 1,
  "displayName": "Alice",
  "relayHandle": "alice-qb-123",
  "deviceId": "pixel-8-primary",
  "publicBundleBase64": "...",
  "identityFingerprint": "AB:CD:EF:01",
  "bootstrapToken": "...",
  "preferredBootstrap": "wifi-direct+ble",
  "turnHint": "relay-assisted-turn"
}
```

## Rules

- `version` is mandatory
- `relayHandle` is stable at the contact identity layer
- `deviceId` identifies the emitting device for device-aware trust decisions
- `identityFingerprint` is the human-facing verification summary
- `publicBundleBase64` is the machine-facing input to session establishment
- bootstrap metadata is advisory and does not imply trust by itself

## Validation requirements

A client importing a bundle must reject it if:

- version is missing or unsupported
- required identity fields are blank
- public bundle bytes are malformed
- fingerprint cannot be derived or checked
