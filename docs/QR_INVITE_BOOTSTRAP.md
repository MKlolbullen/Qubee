# Qubee QR / Invite Bootstrap Pass

This pass removes the worst kind of demo lie: seeded fake contacts with fake peer bundles.

## What changed

- Conversations are no longer pre-seeded with demo contacts.
- The Android shell now exports a **QR-ready invite payload**.
- The app can import another user's invite payload and create a real conversation entry from that bundle.
- A deterministic **safety code** is derived from the local identity and the peer public bundle.
- Contacts can be marked verified after out-of-band comparison.
- The relay protocol now includes a `contact_request` frame so invite bootstrap can propagate through the relay.
- The Rust layer now exposes invite export, invite inspection, and safety-code generation hooks through JNI.

## UI flow

1. Create local identity.
2. Open the Invite screen.
3. Share the `qubee:invite:<base64url>` payload or turn it into a QR code later.
4. Import another user's payload.
5. Review the safety code.
6. Mark the contact verified.
7. Start the first encrypted session/message.

## Important caveat

This is **QR-ready**, not a camera scanner integration yet.
The payload is rendered as text so the project does not pretend to have a full scanning stack when it does not.

## JNI additions

- `nativeExportInvitePayload(identityBundle)`
- `nativeInspectInvitePayload(invitePayload)`
- `nativeComputeSafetyCode(identityBundle, peerPublicBundle)`

## Relay additions

- `contact_request` frame on both Android and Rust relay types
- queued delivery of contact requests for offline recipients in the reference relay server
