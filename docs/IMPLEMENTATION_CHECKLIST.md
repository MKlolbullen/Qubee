# Implementation Checklist

## Done in this scaffold pass
- [x] Honest README
- [x] Android Keystore wrapper scaffold
- [x] SQLCipher / Room construction seam
- [x] Kill-switch wiring scaffold
- [x] FLAG_SECURE on the main activity
- [x] Foreground P2P service scaffold
- [x] Local/WAN signaling transport interfaces
- [x] Rust zeroization entrypoint wired into JNI cleanup

## Still to verify in a real environment
- [ ] SQLCipher package/class compatibility with the chosen Android dependency
- [ ] biometric gating before keystore key use
- [ ] Rust/Android JNI build integration after the new cleanup semantics
- [ ] WorkManager + foreground service interaction under Doze
- [ ] WebRTC data channel bring-up and ICE lifecycle on physical devices
- [ ] BLE / Wi‑Fi Direct local bootstrap
- [ ] onion bootstrap transport on Android
