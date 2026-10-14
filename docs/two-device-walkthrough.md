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
* Both devices on the same local network (one Wi-Fi, or a hotspot
  from one of them), and one of the two discovery routes set up in
  Settings → **Find peers** on both:
  * **Discover peers on this Wi-Fi** switched on. Needs a network
    that passes multicast; most home Wi-Fi does, many corporate
    and guest networks do not (tether off a phone hotspot there).
  * Or **Bootstrap peers**: on A, copy the addresses under **This
    device**; on B, paste them into Bootstrap peers and tap
    **Apply and reconnect**. Works wherever B can reach A's IP,
    multicast or not. One direction is enough.
  Either way, **Connected peers** on both devices must read 1 before
  the steps below; messages queue as `SENT` until it does.
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
   `"AABB CCDD EEFF GGHH"`. This is what the confirm screen
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

There is one confirm screen (`VerifyContactScreen`, hosted by
`ContactVerificationActivity`) and two ways into it:

* **In-chat:** tap the trust line under the contact's name in the
  chat header, or open the details sheet and tap "Confirm it is
  really …". The chat hands the contact's identity id to the
  screen and follows the contact row live, so the header reads
  "Private · Confirmed in person" the moment the ceremony lands.
* **Standalone:** from the Contacts tab, tap "Confirm" on the row
  (or long-press → "Confirm identity").

The screen offers two routes that arrive at the same end-state:

### 4a. Short code (SAS)

The screen leads with an 8-digit "NNNN NNNN" code as two cards.
Both devices independently compute the same code (Rust orders the
byte buffers lexicographically before BLAKE3-hashing them).

1. On device A, open the confirm screen for B.
2. On device B, open the confirm screen for A.
3. Read the code to each other.
4. If it matches, tap "They match" on both devices. The `Contact`
   row updates: `trustLevel = VERIFIED`,
   `verificationStatus = VERIFIED_ONCE`. "They do not match" leaves
   the contact unconfirmed and shows a warning.

### 4b. Fingerprint compare (alternative)

Under "Other ways to check" the screen shows **device A's local
view of B's fingerprint**, computed via
`qubeeManager.computeFingerprint(B's identityKey)`.

1. On device A, read the fingerprint out loud to device B's user.
2. On device B, type it into "Fingerprint read out by A" and tap
   "Check fingerprint", or tap "Scan their code" and point the
   camera at the QR under "Let them scan you" on A's screen.

Behind the scenes on B:
`qubeeManager.verifyIdentityKey(A's contactId, A's identityKey,
typed_bytes)` — the Rust side computes B's local view of A's
fingerprint, normalises spaces and case, compares against the
typed bytes. On match the same row update as 4a lands.

A repeats the same on their side. Now both sides see "Confirmed in
person" persistently. The short code is faster than the
fingerprint and works well over voice; either route writes the
same `Contact` row state.

## 5. Restart & verify persistence

Force-stop both apps; relaunch.

* The chats list shows the previous conversations.
* Opening a confirmed chat should show "Private · Confirmed in
  person" in the top bar (the header follows `Contact.trustLevel`).
* Sending another message round-trips as before — the libp2p
  identity is stable across launches (Ed25519 keypair persists),
  so the contact's `peerId` stays valid.

If "Confirmed in person" reverts to "Not confirmed yet" after
restart, the persistence path is broken — file an issue with the
contact id and the timestamp; `ChatViewModel.applyContact`, which
maps `Contact.trustLevel` to the header, is the likely culprit.

## What's deferred

* **Voice / video calling.** Post-alpha; gated behind the
  Rust `calling` feature flag and an unbuilt `webrtc` integration.

## What's already shipped

(Items previously listed as deferred that have since landed —
useful when running the walkthrough against an older build.)

* **QR-scan flavor of the confirm screen** — "Scan their code" on
  `VerifyContactScreen` feeds the scanned text into the same
  `verifyIdentityKey` JNI path as a typed value. The chat opens
  that same screen; the earlier in-chat dialog is gone.
* **Group chat (>2 members)** — full UX shipped: create a group
  from contact selection, mint invites, accept invites via QR /
  paste, member roster in `GroupDetailsSheet`, Add member /
  Remove / Role picker (owner-only), Leave group, cold-start
  hydration so groups survive an app restart.
* **OOB SAS gesture** — the symmetric SAS code shows on both
  ends of the confirm screen; tapping "They match" persists
  `TrustLevel.VERIFIED` without a bridge round-trip.
* **Ownership transfer** — owners can hand the role to an
  existing active member via the Group Details role picker's
  "Make them the owner" entry; the swap is atomic (donor →
  Admin, target → Owner) via a signed
  `qubee_handshake_ownership_transfer_v1` wire frame, no group
  key rotation needed.
* **Delivery confirmation** — every successful decrypt fires a
  signed `MessageAck` back on the group's gossipsub topic; the
  sender's local Message row flips from `SENT` to `DELIVERED`
  on first ack arrival and tracks per-recipient delivery in
  `deliveredAckers` for "delivered to N of M" hints. No bridge
  round-trip on the receiver side; the auto-ack runs Rust-side
  inside `handle_inbound_group_message`.
* **Schema migrations** — v2→v3 migration in
  `Migrations.kt` adds the `wireId` / `deliveredAckers` columns
  without wiping the inbox. Future bumps follow the same
  pattern; the destructive fallback stays as a safety net.

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
  group, or libp2p isn't routing). Check Settings → Find peers on
  both: **Connected peers** must be at least 1. Wi-Fi discovery is
  fragile across screen-off and on networks that drop multicast;
  the bootstrap-address route redials every 30 seconds and does
  not depend on multicast.
* **"Verification bridge unreachable"**: the
  `nativeVerifyIdentityKey` JNI symbol failed to load. Means the
  shared library didn't link the Rust bridge — check the build
  output of `build_rust.sh` for the target ABIs your device uses.

## Ratchet cutover checklist (Stage 3d validation)

The PQXDH + Double Ratchet 1:1 path is fully implemented and exposed
over JNI (`installPeerPrekeyBundle` / `encryptDirectMessage` /
`decryptDirectMessage` / `inspectDirectMessageSender` on
`QubeeManager`), but **dark**: `MessageService` still routes live 1:1
traffic through the legacy envelope. Before flipping the default,
validate on two devices:

1. **Bundle exchange.** A and B each call `buildLocalPrekeyBundle` and
   deliver the frame to the other device (over the group topic or any
   authenticated channel); `installPeerPrekeyBundle` must return the
   peer's identity id hex on both sides. Without this, both directions
   fail closed by design.
2. **First contact.** A sends via `encryptDirectMessage(bIdHex, …)`;
   B routes the received bytes (recognised via
   `inspectDirectMessageSender != null`) into `decryptDirectMessage`
   and sees the plaintext. Repeat B→A.
3. **Restart persistence.** Force-stop both apps, reopen, exchange
   another pair of messages — sessions must resume from the keystore
   with no re-handshake.
4. **Lossy first message.** Clear app data on B only, re-exchange
   bundles, have A send *two* messages, deliver only the second — it
   must still decrypt (the initial rides every frame until A first
   hears back).
5. **Replay.** Re-deliver an already-decrypted frame — must return
   null, and the next fresh message must still decrypt.
6. **Simultaneous open.** Both devices send their first message before
   either receives. The byte-wise-smaller identity id wins the
   initiator role; the other side's first send is dropped (expected —
   note it in the test log) and everything after converges.

Only after all six pass does the send path in `MessageService` switch
from the legacy envelope to `encryptDirectMessage`.

## Group sender-keys checklist (Stage 4 validation)

The v3 group format (`createSenderKeyDistribution` /
`installSenderKeyDistribution` / `encryptGroupMessageV3` /
`decryptGroupMessageV3` on `QubeeManager`) is likewise dark. It
depends on the 1:1 ratchet path above — distributions travel inside
`encryptDirectMessage` frames. Validate with three devices in one
group (A owner, B, C members), after the 1:1 checklist passes between
every pair:

1. **Distribution fan-out.** Each device calls
   `createDirectDistributionMessage(peerIdHex, groupIdHex)` once per
   other member and sends the frames over the P2P transport. On
   receipt, `decryptDirectMessage` returns
   `{"kind": "senderKeyDistribution", "groupId": …}` — Rust has
   already membership-checked and installed it. All six deliveries
   must return that JSON shape.
2. **Group round-trip.** A sends via `encryptGroupMessageV3`; B and C
   both decrypt and see `senderId == A` in the returned JSON. Repeat
   from B and C.
3. **Out-of-order + replay.** Hold back one of A's frames, deliver a
   later one first, then the held frame — both decrypt. Re-deliver
   either — must return null.
4. **Member removal rekey.** Remove C via the existing flow. The
   rotation wipes sender chains automatically on every device that
   processes it (verify `resetGroupSenderState` returns 0 afterwards —
   nothing left to delete). Re-run step 1 among A+B; A↔B traffic must
   resume on fresh chains, and C must decrypt nothing sent after the
   rotation.

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
