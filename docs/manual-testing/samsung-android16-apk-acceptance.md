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
