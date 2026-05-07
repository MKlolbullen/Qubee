# Two-device manual walkthrough

End-to-end flow for testing Qubee on two physical devices (or two
emulators on the same loopback). Covers onboarding both sides,
pairing via an invite link, exchanging a 1:1 message, and
performing the OOB verification ceremony.

Status: this walkthrough exercises the surface that's actually
shipped today. Items the codebase doesn't yet support are called
out as **deferred** — those steps are stubs the user has to
believe instead of seeing real behavior.

## Prerequisites

* Two devices running Qubee. Easiest path is to download the
  signed APK from the latest GitHub Release and `adb install` it on
  both — see `RELEASE.md` for the build / release pipeline. If
  you're building from source for development,
  `./build_rust.sh && ./gradlew installDebug` works too. Mixing a
  release-signed install on one device with a debug-built install
  on the other is fine — invite signatures use the user's
  per-install identity key, not the APK signing cert. The only
  caveat is that `adb install` over an existing install with a
  different signing cert needs `adb uninstall` first.
* Both devices on the same local network so libp2p mDNS / loopback
  TCP can find each other. mDNS-only deployments also work as long
  as the network doesn't suppress multicast (most home Wi-Fi
  networks do; tether off a phone hotspot if the corporate network
  blocks it).
* Notification permission granted on both devices (the foreground
  P2P service runs under
  `NOTIFICATION_CHANNEL_SERVICE`).

Refer to devices as A and B in the steps below.

## 1. Onboarding (both devices)

On first launch, each device runs through `OnboardingScreen`:

1. Pick a display name. Stored locally, included in invite links
   so the other side sees a label.
2. Tap "Generate identity". Behind the scenes:
   * `QubeeManager.initialize()` opens the encrypted Rust keystore
     under `context.filesDir/qubee_keys.db` and
     `qubee_groups.db`.
   * `nativeCreateOnboardingBundle(displayName, userId)` mints a
     hybrid Ed25519 + ML-DSA-44 + ML-KEM-768 identity, signs the
     bundle, persists the keypair, and returns the JSON bundle plus
     the `qubee://identity/<token>` deep link.
3. The screen displays your 8-byte BLAKE3 fingerprint:
   `"AABB CCDD EEFF GGHH"`. This is what the verification dialog
   displays later — the format is canonical, both devices see the
   same string for the same identity bytes.

Do this on A and B. They now have separate, independent Qubee
identities.

## 2. Pair A → B via invite link

On device A:

1. Tap "Add contact" → "Invite a peer".
2. The screen displays a `qubee://identity/<token>` deep link as
   both a tappable URL and a QR code.
3. Show the QR to device B (or share the URL via any out-of-band
   channel — your choice).

On device B:

1. Tap "Add contact" → "Scan invite". The CameraX scanner reads
   the QR.
2. The link is parsed:
   `QubeeManager.verifyOnboardingLink(link)` checks the embedded
   hybrid signature against the advertised public key. Tampered or
   replayed links are rejected; you'll see a "Invalid identity
   link" notice.
3. On verify-pass, device B's `ContactsFragment` shows a "Confirm
   add" panel with A's display name and fingerprint.
4. Tap "Add". A new `Contact` row lands in B's local database with
   `identityId`, `identityKey`, `displayName` populated. `peerId`
   stays null until the first inbound message — the
   `MessageService.onPeerLinked` callback fills it.

Symmetric: A doesn't yet know about B. **Add A on device B's
identity link too** by repeating the flow in the other direction.
After this, both devices have a `Contact` row for the other.

## 3. First conversation + message

On device A:

1. Tap on B's Contact row in the contacts list. ChatScreen opens.
2. Behind the scenes:
   * `ChatViewModel.init` calls
     `ConversationRepository.getOrCreateConversationId(B's
     contactId)`.
   * No matching DIRECT conversation exists yet, so the repo
     calls `qubeeManager.createGroup("1:1 with <B>")`. The Rust
     `nativeCreateGroup` mints a fresh 32-byte `GroupId`, returns
     `{group_id_hex, name, owner_id_hex}`. A row lands in
     `conversations` with `id = group_id_hex`.
3. The chat is empty. The security badge in the top bar reads
   "Unverified" — yellow, with an "ErrorOutline" icon.
4. Type "hello B" and tap send.
5. Behind the scenes:
   * `MessageRepository.saveMessage(...)` persists the row at
     status `SENDING`.
   * `qubeeManager.encryptMessage(conversationId, "hello B")`
     wraps the plaintext in a signed `GroupMessageEnvelope`.
   * `qubeeManager.sendP2PMessage(B's contactId, encrypted bytes)`
     queues the libp2p publish on the group's gossipsub topic.
   * Status flips to `SENT` once libp2p accepts the queue.

**Expected state on B**: `MessageService.onMessageReceived` fires.
Behind the scenes:

* `ContactRepository.getContactByPeerId(senderId)` returns null
  (peerId isn't populated yet).
* `populateContactPeerId` reads the wire envelope's signed
  `sender_id` field via `nativeInspectEnvelopeSender`, looks up
  Contact by `identityId`, finds A, and stamps
  `Contact.peerId = senderPeerId`.
* `ConversationRepository.getOrCreateConversationId(A's contactId)`
  reuses the same `group_id_hex` if A's earlier `MemberAdded`
  broadcast landed (it should — that's the auto-created group
  from step 2). If for some reason it doesn't, B's local
  `conversations` row gets created here.
* `decryptMessage` returns "hello B"; the message lands in
  ChatScreen if B has the chat open.

If B is in the chat with A, the message appears as an inbound
bubble with status `DELIVERED`. If B is not in that chat, it
shows in the conversations list with an unread badge.

## 4. OOB verification ceremony

The chat surface alone gets you transport-encrypted, signed, and
post-quantum-protected messaging. What it doesn't get you is
*identity verification* — at no point in the above did either
device confirm the OTHER side actually holds the identity their
keys claim. A passive man-in-the-middle could substitute a
different identity in the QR scan; the handshake would succeed
because the MITM signs everything correctly with their own key.
The OOB ceremony is what closes that gap.

There are two entry-points to the same ceremony:

* **In-chat:** open the chat with the contact, tap the details
  arrow, then `Verify`. Renders the same widget as an
  `AlertDialog` over the chat.
* **Standalone:** from the Contacts tab, long-press the contact
  and tap `Verify` (or `Re-verify` if the row already shows the
  cyan check). Launches `ContactVerificationActivity`, which
  hosts the same widget as a full-screen Scaffold — preferred
  when both devices are co-located and you want a larger QR for
  scanning.

Both surfaces accept **two** routes that arrive at the same
end-state:

### 4a. Fingerprint compare

On device A:

1. Tap the contact's name in the chat top bar → details sheet
   appears.
2. Tap "Verify". The sheet closes; the verification dialog opens.
3. The dialog shows a `"AABB CCDD EEFF GGHH"` string —
   **device A's local view of B's fingerprint**, computed via
   `qubeeManager.computeFingerprint(B's identityKey)`.
4. Read this string out loud to device B's user.

On device B:

1. Open the chat with A; tap details → "Verify".
2. Type (or paste) the string A read out into the "Fingerprint
   from contact" field.
3. Tap "Verify".

Behind the scenes on B:
`qubeeManager.verifyIdentityKey(A's contactId, A's identityKey,
typed_bytes)` — the Rust side computes B's local view of A's
fingerprint, normalises spaces and case, compares against the
typed bytes. On match, B's `Contact` row updates:
`trustLevel = VERIFIED`, `verificationStatus = VERIFIED_ONCE`.
The security badge flips to "Verified" — cyan, with the
`VerifiedUser` icon. The dialog dismisses.

A repeats the same on their side (typing the fingerprint B
dictates). Now both sides see "Verified" persistently.

### 4b. SAS compare (alternative)

Same dialog. Below the fingerprint section, an 8-digit
"NNNN NNNN" code is displayed prominently. Both devices
independently compute the same code (Rust orders the byte
buffers lexicographically before BLAKE3-hashing them).

1. On device A, open the verify dialog.
2. On device B, open the verify dialog.
3. Both users look at the SAS code on their respective screens.
4. If the codes match, tap "Codes match" on both devices. The
   trust ceremony is complete; persistence + UI flip identical to
   4a.

SAS is faster than fingerprint compare — 8 digits versus 16 hex
characters with separators — and works well over voice. Either
ceremony writes the same `Contact` row state.

## 5. Restart & verify persistence

Force-stop both apps; relaunch.

* The chats list shows the previous conversations.
* Opening a verified chat should show "Verified" in the top bar
  (the badge respects `Contact.trustLevel`).
* Sending another message round-trips as before — the libp2p
  identity is stable across launches (Ed25519 keypair persists),
  so the contact's `peerId` stays valid.

If "Verified" reverts to "Unverified" after restart, the
persistence path is broken — file an issue with the contact id
and the timestamp; the
`ChatViewModel.init`-reads-`contact.trustLevel` path is the
likely culprit.

## What's deferred

* **Delivery confirmation.** Status = `SENT` today means
  "encrypted bytes left this device", not "peer ack'd". A real
  ack roundtrip is post-alpha.
* **Voice / video calling.** Post-alpha; gated behind the
  Rust `calling` feature flag and an unbuilt `webrtc` integration.
* **Ownership transfer.** A group's owner is the original creator
  forever; promote/demote can move other members between Admin /
  Moderator / Member / Observer but cannot transfer Owner. Tracked
  for v0.2.x.
* **Schema migrations.** `fallbackToDestructiveMigration` resets
  the local DB on every minor-version bump until v0.2.0 commits to
  schema stability.

## What's already shipped

(Items previously listed as deferred that have since landed —
useful when running the walkthrough against an older build.)

* **QR-scan flavor of the verify dialog** — landed in the in-chat
  `VerifyContactDialog` and in the new `VerifyContactScreen` that
  `ContactVerificationActivity` hosts (long-press a contact →
  Verify). Both routes feed the scanned text into the same
  `verifyIdentityKey` JNI path as a typed value.
* **Group chat (>2 members)** — full UX shipped: create a group
  from contact selection, mint invites, accept invites via QR /
  paste, member roster in `GroupDetailsSheet`, Add member /
  Remove / Role picker (owner-only), Leave group, cold-start
  hydration so groups survive an app restart.
* **OOB SAS gesture** — the symmetric SAS code shows on both
  ends of the verify screen; tapping "Codes match" persists
  `TrustLevel.VERIFIED` without a bridge round-trip.

## Troubleshooting

* **"Encrypt failed — peer may not have accepted the group invite
  yet"** on send: the local Rust group exists but the contact
  hasn't joined it through the handshake yet. Re-share the invite
  link; have them tap it on their device. The contact appears as
  a Member of the group only after their `RequestJoin` completes
  on your side.
* **"P2P send failed"**: libp2p couldn't queue the publish.
  Usually means the peer isn't currently reachable on the topic
  mesh. Wait for them to come online, send again. Real
  store-and-forward / offline queue is post-alpha.
* **No message arrives on B even though A sees `SENT`**: the
  group key isn't shared yet (B isn't an active member of the
  group, or libp2p isn't routing). Check that B's app is
  foregrounded (the foreground service stays alive in the
  background, but mDNS discovery is fragile across screen-off).
* **"Verification bridge unreachable"**: the
  `nativeVerifyIdentityKey` JNI symbol failed to load. Means the
  shared library didn't link the Rust bridge — check the build
  output of `build_rust.sh` for the target ABIs your device uses.

## Build commands

```bash
# Build the Rust shared library for all Android ABIs.
./build_rust.sh

# Type-check the JNI surface on the host (no Android target
# needed). CI runs this too — keeps regressions visible without
# an emulator.
cargo build --features _typecheck_jni

# Run the Rust test suite.
cargo test --no-fail-fast

# Build + install the debug APK on a connected device.
./gradlew installDebug
```
