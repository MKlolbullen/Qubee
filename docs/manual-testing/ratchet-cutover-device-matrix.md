# Ratchet cutover — physical-device validation matrix (Category B)

Part of the **v0.2.0 — Ratchet Cutover** milestone (#47). Before flipping
`ratchetSendEnabled` to true by default and retiring the legacy envelope,
the cutover matrix has to go green. It splits in two:

- **Category A — automated in separate layers** (host/emulator, CI-gating). The
  crypto correctness — PQXDH establishment, DH ratchet advance, sustained
  no-desync, out-of-order/skip-window, replay/tamper rejection, cross-
  group/cross-session isolation, restart survival, group future-only +
  removal rekey, and persisted chain advancement — is exercised through
  Rust APIs in `tests/ratchet_cutover_e2e.rs` and primitive unit tests.
  Rust store reopen is not Android process death. Room recovery tests
  exercise a separate durability boundary; neither suite proves the
  entire Room ↔ Kotlin ↔ JNI ↔ Rust ↔ network crash window.
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
  reference pass; an OEM skin failing a required row remains a cutover
  blocker until resolved and revalidated.
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

### 13. Fresh PQXDH establishment, reply, and future-only group join
- **Procedure:** With explicit ratchet opt-in on fresh A/B installs, exchange
  signed prekey bundles, send A→B, reply B→A, and alternate 100 messages.
  In an A/B group, retain pre-join packets, add C, then send new traffic.
- **Expected:** Authenticated text arrives without desync. C reads new
  traffic but cannot decrypt retained pre-join packets.
- **Exercises:** live prekey exchange, ratchet advancement, and sender-key
  distribution on join (not just the host choreography).

## Automated evidence and remaining blockers

Local host validation for this focused #47 PR (2026-10-10):

| Command | Result |
|---|---|
| `cargo test --locked --test ratchet_cutover_e2e` | 14 passed |
| `cargo test --locked --test wire_stability` | 29 passed |
| `cargo test --locked --test wire_parser_robustness` | 10 passed |
| `cargo fmt --all -- --check` | passed |
| `cargo clippy --locked --all-targets -- -D warnings` | passed |
| `cargo test --locked --all-targets` | 259 tests passed; 7 benchmark smoke cases succeeded |
| `bash scripts/check_jni_contracts.sh` | 62/62 symbols; reverse callback descriptors match |
| `bash scripts/audit_message_file_bridge.sh` | passed (symbol presence only) |

The added host cases check persisted skipped keys across a DH step and
store reopen, header/ciphertext rejection without durable state mutation,
duplicate rejection after reopen, and group delayed-key/rekey persistence.
An actual filesystem rename failure during fresh/established direct
encryption returns no wire, poisons the store until reopen, and leaves the
previous snapshot usable. This tests Rust commit failure, not Room failure.

`MessageDaoInstrumentedTest` adds file-backed Room close/reopen tests:
an aborting SQLite trigger on the real INSERT/REPLACE queue operation
leaves the PREPARED text intact, recovery marks it FAILED; a durable
SENDING row is promoted once and selected for retry with the exact bytes,
wire id, schedule, and attempt count. Inbound, terminal, and no-wire rows
are not promoted. These tests do **not** call JNI or encrypt real packets.
The production PREPARED intent still lacks a durable recipient identity
field; targeted retry/recipient binding from #56 remains a prerequisite.

Android compilation was attempted with
`./gradlew :app:compileDebugAndroidTestKotlin --no-daemon`, but stopped at
AGP 8.4.0 plugin resolution before source compilation. Thus the new Room
tests and default-OFF preference unit test are **unverified locally**;
the existing instrumented workflow runs them on API 34, and the existing
Android smoke workflow runs JVM tests. Current PR Actions require approval
(`action_required`, no jobs/logs); no remote CI success is claimed.

Golden vectors now pin full direct frames with/without PQXDH initial and
sender-key distributions, not only magic bytes/round trips. Bounded
direct-frame proptests and malformed/oversized tests run in the existing
`cargo test --locked --all-targets` CI gate. No workflow files changed.
Coverage-guided fuzz campaigns remain pending (`fuzz/README.md`); no fuzz
campaign success is inferred from proptest.

Reproducibility remains **unverified**: pinned inputs and printed `.so`
hashes in `build_rust.sh` are not an independent two-build comparison.
Follow `docs/reproducible-builds.md` with identical locked inputs and record
per-ABI hashes plus unsigned APK-content comparison from independent clean
builds. No APK/NDK reproducibility result is claimed here.

### Manual Category B evidence checklist (all pending)

For each row record commit/APK hash, device/OEM, OS version, release/R8
configuration, explicit ratchet opt-in, procedure, expected/actual result,
timestamp, and log/report location. Never attach plaintext or key material.

- [ ] Rows 1–3: offline delivery, both-process death, send-window recovery
- [ ] Row 4: reboot both phones and recover identities/session/outbox
- [ ] Rows 5–6: Wi-Fi↔LTE and airplane→online retry
- [ ] Row 7: Doze/background kill on near-AOSP and OEM devices
- [ ] Row 8: R8-on-device JNI callbacks and receipt handling
- [ ] Row 9: auth-bound Keystore/SQLCipher inaccessible before unlock
- [ ] Rows 10–11: reinstall/key change invalidates verified trust
- [ ] Rows 12–13: live fresh PQXDH/reply, future-only join, immediate
  removal/rekey, removed-member old-state rejection

## Exit

Only when every required physical-device criterion is recorded green,
including rows 1–13 on a **release** build across at least two
distinct OEMs (row 7 especially), flip `ratchetSendEnabled` to true by
default and remove the legacy signed-envelope emission — tracked in #47.
Until then the default remains **OFF**, explicit opt-in is only for
validation, and legacy signed-envelope emission stays available. This PR
is progress toward #47, not closure of the epic.
