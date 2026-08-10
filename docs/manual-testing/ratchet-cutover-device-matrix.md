# Ratchet cutover — physical-device validation matrix (Category B)

Part of the **v0.2.0 — Ratchet Cutover** milestone (#47). Before flipping
`ratchetSendEnabled` to true by default and retiring the legacy envelope,
the cutover matrix has to go green. It splits in two:

- **Category A — already automated** (host/emulator, CI-gating). The
  crypto correctness — PQXDH establishment, DH ratchet advance, sustained
  no-desync, out-of-order/skip-window, replay/tamper rejection, cross-
  group/cross-session isolation, restart survival, group future-only +
  removal rekey, and **no key reuse across a crash** — is proven in
  `tests/ratchet_cutover_e2e.rs`, and parser robustness in
  `tests/wire_parser_robustness.rs`. Don't re-do those by hand.
- **Category B — this document.** The device-environment and lifecycle
  behaviours that emulators can't fake: Doze, network transitions, R8
  minification, the auth-bound datastore, reboot, and reinstall/identity
  change. These need real hardware.

For the protocol-correctness walkthrough (bundle exchange, first contact,
etc.) follow `docs/two-device-walkthrough.md` (Stage 3d / Stage 4
checklists) first — this runbook assumes two paired devices that already
exchange 1:1 and group messages.

## Setup

- **Two physical phones**, A and B (a third, C, for the group rows).
  Prefer an `assembleRelease` (R8-minified) install for at least one
  device — several rows only fail on the minified build.
  `adb install -r app/build/outputs/apk/release/app-release.apk`.
  Easiest source: run the **"Build APK (on demand)"** workflow
  (Actions tab, pick the branch under test) and download the artifact —
  it contains a debug APK and a debug-signed R8 release APK, both
  `apksigner`-verified installable, with SHA256SUMS.
- **Minimum device coverage** for the OEM-sensitive rows (7 Doze, 8 R8):
  at least one near-AOSP device (Pixel / Android One) **and** one
  aggressive-background-management OEM skin (Samsung One UI or Xiaomi
  MIUI/HyperOS), spanning **Android 12–15**. The near-AOSP device is the
  reference pass; an OEM skin failing row 7 is a deployment caveat (see
  Exit), not necessarily a blocker.
- `ratchetSendEnabled` **on** for the run (Settings → developer toggle,
  or `PreferenceRepository`). The whole point is validating the live
  ratchet path, not the legacy envelope.
- `adb logcat -s Qubee MessageService` on both devices to watch delivery
  + the crash-recovery lines (`crash recovery: … PREPARED`, `… orphaned
  SENDING`).
- Record each row Pass/Fail with the device build type (debug/release)
  and Android version — several rows are OEM/version-sensitive.

## The matrix

Each row: **procedure → expected → what it exercises**. A row is Pass only
if the expected result is observed on a **release** build unless noted.

### 1. Receiver offline → queued delivery
- **Procedure:** Put B in airplane mode. A sends 3 messages. Wait ~30 s.
  Bring B online.
- **Expected:** All 3 arrive at B, in order, decrypting correctly; A's
  rows move `SENDING`/`SENT` → `DELIVERED` as acks land.
- **Exercises:** the offline retry loop + idempotent re-publish
  (`MessageService.runOfflineRetryTick`), ack correlation by `wireId`.

### 2. Process death mid-conversation → state survives
- **Procedure:** Exchange a few messages. `adb shell am force-stop
  com.qubee.messenger` on **both**. Reopen both. Exchange another pair.
- **Expected:** Sessions resume from the keystore with no re-handshake;
  new messages decrypt. No duplicate or lost message in the transcript.
- **Exercises:** keystore-backed ratchet persistence; the crash-
  consistency startup recovery (`docs/architecture/crash-consistency.md`).

### 3. Process death in the send window → no silent loss
- **Procedure:** This targets the encrypt→persist window. Enable "Don't
  keep activities" (Developer options). Type a long message on A and hit
  send while backgrounding immediately (or `am kill` A within the same
  second). Reopen A.
- **Expected:** The message is **never silently gone** — it shows either
  `DELIVERED`/`SENT` (recovery re-published it) or `FAILED` with the
  typed text preserved for one-tap resend. Never a blank/vanished row.
  On B, at most one copy (idempotent), never a key-reuse decrypt error on
  subsequent traffic.
- **Exercises:** the `PREPARED` state + `failStalePreparedOutbound` /
  `recoverOrphanedSendingOutbound` recovery.

### 4. Reboot both phones → state survives
- **Procedure:** `adb reboot` both. After boot, without reopening the app
  first if possible, have A send; then open B.
- **Expected:** The foreground service restarts, re-subscribes to group
  topics, and delivery resumes; identities and sessions intact.
- **Exercises:** cold-start persistence + `MessageService` lifecycle +
  `resubscribe_known_groups`.

### 5. Wi-Fi → LTE transition → reconnect
- **Procedure:** On Wi-Fi, confirm live delivery. Disable Wi-Fi (fall to
  LTE) mid-conversation. Send from both directions.
- **Expected:** After a brief reconnect, messages flow again; queued
  messages drain. No permanent stall.
- **Exercises:** libp2p transport re-dial / QUIC+TCP fallback after an
  interface change.

### 6. Airplane mode → online → retry succeeds
- **Procedure:** Airplane mode on A while it has `SENDING` rows. Wait past
  one retry interval. Airplane mode off.
- **Expected:** The retry loop re-publishes on reconnect; rows reach
  `DELIVERED`. Retry backoff visible in logcat.
- **Exercises:** retry backoff schedule + reconnect-driven drain.

### 7. Doze / background kill at a bad moment
- **Procedure:** Force Doze: `adb shell dumpsys deviceidle force-idle`.
  Send from the peer to the dozing device; also `am kill` the dozing
  app. `adb shell dumpsys deviceidle unforce` and open the app.
- **Expected:** No message lost; delivery completes once the app/service
  is scheduled again. Note any OEM (Samsung/Xiaomi/etc.) that kills the
  service more aggressively — that's a real deployment finding.
- **Exercises:** foreground-service survivability + queued delivery under
  Doze. **The row most likely to expose OEM-specific breakage.**

### 8. R8 release build → JNI callbacks still fire
- **Procedure:** Install the `assembleRelease` APK on both. Run rows 1–2.
  Watch for `NetworkCallback` / `onMessageReceived` / `onMessageAcked` /
  `onPeerLinked` firing (logcat).
- **Expected:** All native → Kotlin callbacks fire; no
  `NoSuchMethodError` / missing-symbol crash. If a callback is stripped,
  R8 `keep` rules need widening.
- **Exercises:** the JNI reverse-callback surface survives minification
  (`scripts/check_jni_contracts.sh` guards the symbol set at build time,
  but only a device proves the reflective call path).

### 9. Screen lock → datastore inaccessible before unlock
- **Procedure:** Enable Screen Lock binding (Settings). Lock the device /
  cold-start with the screen locked. Observe the app before biometric/PIN
  unlock.
- **Expected:** The message datastore cannot be opened until a
  biometric/PIN unlock; no plaintext or DB read succeeds while locked.
  After unlock, normal operation resumes.
- **Exercises:** the auth-bound SQLCipher key + per-use `CryptoObject`.

### 10. A reinstalls Qubee → identity-change warning on B
- **Procedure:** `adb uninstall` then reinstall on A (fresh identity).
  A re-pairs and messages B.
- **Expected:** B surfaces an **identity-changed / re-verify** warning for
  A; a previously **Verified** contact drops to `KeyChanged`, never
  silently stays Verified.
- **Exercises:** TOFU trust-state transition (`TrustStatePolicy` — the
  "Verified + changed key = KeyChanged" invariant).

### 11. B changes identity → old trust invalidated
- **Procedure:** As row 10 but from B's side, with A having previously
  **Verified** B.
- **Expected:** A invalidates the old trust and requires re-verification;
  no message is auto-trusted under the new key.
- **Exercises:** the same trust invariant from the other direction.

### 12. Removed group member cannot decrypt future traffic (on-device)
- **Procedure:** Three devices in a group; remove C. A and B keep
  messaging.
- **Expected:** C decrypts nothing sent after the rotation (fresh sender
  chains); A↔B continue. (Category A proves the crypto; this confirms it
  end-to-end on hardware with the real removal flow.)
- **Exercises:** removal rekey + chain wipe over the live transport.

## Exit

When rows 1–12 pass on a **release** build across at least two
distinct OEMs (row 7 especially), flip `ratchetSendEnabled` to true by
default and remove the legacy signed-envelope emission — tracked in #47.
Log any OEM that fails row 7/8 as a deployment caveat rather than a
blocker on the default flip, unless it drops messages outright.
