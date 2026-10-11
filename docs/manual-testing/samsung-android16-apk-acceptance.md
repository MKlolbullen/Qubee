# Samsung Android 16 minified APK acceptance

Status: NOT RUN. Run this on physical hardware; CI and signature verification do not establish runtime security readiness.

Use the qubee-release-debugsigned.apk and SHA256SUMS from the Android Build Smoke artifact for the exact PR head. This is an R8-minified test build, signed with a debug certificate. It is not a production release. Verify SHA256SUMS and compare the apksigner certificate output in CI before installing. Installing over a differently signed app fails; uninstalling deletes local identities and messages, so do not uninstall an existing valuable installation casually.

## Record evidence

Record model, Android version, One UI version, APK SHA256, commit, signer fingerprint, ratchet setting and Pass/Fail for each row below. Never include message content, identity private keys or passphrases in shared logs. Use disposable test identities and synthetic messages.

## Procedure

Pair the Samsung with a second physical phone; use a third for group removal. Follow docs/manual-testing/ratchet-cutover-device-matrix.md for detailed procedures. Enable ratchet sending explicitly in the developer setting if disabled.

| Check | Required result |
| --- | --- |
| Cold launch / onboarding | No crash, native library loads, identity persists |
| Direct messages in both directions | Correct plaintext once only; tampered/replayed frames rejected |
| Offline recipient then reconnect | Queued messages delivered; acknowledgements correlate |
| Process death and restart | Identities/sessions survive; no key reuse or silent send loss |
| Reboot | State survives; delivery resumes when Android schedules the app |
| Wi-Fi to mobile data | Reconnect succeeds and queued messages drain |
| Doze and Samsung background restrictions | Delivery resumes without duplicates or lost messages |
| Biometric lock, cancel and background | Cancel grants no access; locking closes datastore access as designed |
| Peer identity reset/change | Trust warning appears; sending follows the documented trust policy |
| Group member removal | Removed member cannot decrypt messages after the rekey |
| R8 paths: QR links, JNI callbacks, attachments | No missing methods or serialization failures |

Useful commands from a computer with adb:

```sh
sha256sum -c SHA256SUMS
adb install -r qubee-release-debugsigned.apk
adb shell am force-stop com.qubee.messenger
adb shell dumpsys deviceidle force-idle
adb shell dumpsys deviceidle unforce
```

Always unforce Doze after the test. Do not call this build ready for sensitive conversations until dependency/security gates pass and the device results are recorded. A report that failed to generate is not a clean scan.

## Pool/rotation and product-signing acceptance

New pool setup requires both phones to run this commit or later. The first migration retains the deniable identity and existing conversations; legacy-only new setup stops after the bounded migration window. Seven-day rotation and secret-pruning boundaries are covered with deterministic host clocks. Changing a live phone's system clock is not equivalent to those tests and can invalidate unrelated identity signatures.

Before manual testing, collect a preflight record (use the test certificate for a test APK, the pinned owner certificate for a product APK):

```sh
python3 scripts/samsung_preflight.py \
  --apk PATH_TO_EXACT_APK --source-commit FULL_REVIEWED_COMMIT_SHA \
  --certificate-sha256 EXACT_APK_CERTIFICATE_SHA256 \
  --samsung SAMSUNG_ADB_SERIAL --peer SECOND_PHONE_ADB_SERIAL \
  --output samsung-run-001.json
```

Add `--install` only when these are disposable test installations or certificate-compatible upgrades. The helper never uninstalls or clears data. It rejects emulators, disconnected phones, certificate mismatch and API below 34. Preflight PASS only records prerequisites; all physical acceptance rows start NOT RUN.

The following are proposed hard gates for the first Samsung run. Record results for both directions and attach synthetic-message counts/timings and sanitized diagnostics to each row. No row can be inferred from CI.

| Gate | Exact acceptance for this first run | Current status |
| --- | --- | --- |
| S0: product identity | Owner certificate pin matches, v2/v3 verify, R8 enabled, versionCode increases; update over the previous same-signer APK preserves identities and messages. Debug-signed test builds cannot pass the product gate. | BLOCKED: owner key unavailable |
| S1: hardware/onboarding | Two physical phones, Samsung plus peer, both API 34+; record Android/One UI/page size; 3 cold starts and 1 reboot per device without JNI/R8 failure. Verify the two identities by SAS/QR comparison. | NOT RUN |
| S2: messages/pool | Fresh pool-based setup; 50 synthetic messages each direction, correct plaintext and one delivery record per message; refresh publication and repeat after restart. Host tests must also pass exact-ID consumption, expiry, invalid AEAD rollback and delayed epoch selection. | NOT RUN (host coverage separate) |
| S3: persistence/retry | 10 force-stop/restart cycles per device, including queued sends before delivery acknowledgement; 20 messages queued while recipient offline then delivered once after reconnect. Existing identities and working conversations survive. Physical behavior alone does not prove nonce/state non-reuse. | NOT RUN |
| S4: network/OEM | 10 Wi-Fi→cellular→Wi-Fi cycles; 30 minutes screen-off/Doze with Samsung's default battery policy, then repeat with restrictive background policy. Delivery resumes within 60 seconds after both apps regain network and execution; no duplicate or lost accepted messages. Record whether background delivery was suspended. | NOT RUN |
| S5: fail-closed calling | With empty TURN configuration, 10 start attempts terminate with an explicit configuration error and no capture starts. Separately, startup with unavailable private signaling must fail even with valid TURN. The current true development override cannot pass that second requirement; direct libp2p exposes IP metadata. | TURN case NOT RUN; private-signaling case BLOCKED |
| S6: functional media | Requires configured authenticated TURN and actual relay/private signaling. 10 calls initiated by each phone; all connect within 15 seconds, both directions audible, clean hangup. 10 network switches and 10 explicit ICE-restart trials; recovery within 15 seconds with no direct-candidate fallback. | BLOCKED: infrastructure/device evidence absent |
| S7: background/API 34+ | With S6 prerequisites, 30-minute call screen-off, Home/background, Doze, microphone permission revoke/cancel and competing audio focus; no crash/ANR, hidden continued capture or orphaned microphone service. Capture ends within 2 seconds of hangup/revoke. | BLOCKED: S6 prerequisites |
| S8: thermal/battery | With S6 prerequisites, 60-minute audio call and 20-minute video call per direction, unplugged, record ambient conditions/start-end charge/thermal status and route. No thermal status MODERATE-or-worse, forced shutdown or persistent audio/video stall; first-run budget ≤10 charge percentage points/hour audio and ≤25/hour video (video budget scaled to 20 minutes). | BLOCKED: S6 prerequisites |

Thresholds above are acceptance policy, not measured performance or platform guarantees. A failed/blocked/unrun gate prevents a product/release-candidate claim for that feature. Successful messaging acceptance cannot substitute for S5–S8 calling results. Calling remains opt-in and disabled in the default APK; a calling build additionally requires the native feature and matching Gradle flag documented in README.
