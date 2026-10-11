# Product APK signing and Samsung handoff

A product APK must be signed by the owner's long-lived app signing key. The Android app signer is separate from Qubee's per-user messaging identities and prekeys. Prekey rotation never changes the app signer.

## Existing product key

Keep the private keystore outside the repository. Supply these environment variables without placing passwords on command lines or in Git:

- `RELEASE_KEYSTORE_FILE`
- `RELEASE_KEYSTORE_PASSWORD`
- `RELEASE_KEY_ALIAS`
- `RELEASE_KEY_PASSWORD`

Build from the reviewed commit:

```sh
./build_rust.sh
./gradlew :app:assembleRelease --no-daemon \
  -PqubeeRequireReleaseSigning=true \
  -PqubeeVersionName=0.2.0-beta.1 -PqubeeVersionCode=YOUR_MONOTONIC_CODE
python3 scripts/sign_product_apk.py \
  app/build/outputs/apk/release/app-release.apk qubee-product.apk \
  --certificate-sha256 YOUR_EXISTING_PUBLIC_CERTIFICATE_SHA256
```

The helper aligns the APK, signs with v2/v3 schemes using environment passwords, verifies both schemes, requires exactly the expected certificate and refuses an Android Debug signer or missing arm64 native library. A matching certificate verifies build ownership; it does not establish runtime security. Choose a fresh output path: existing artifacts are never overwritten.

For the release workflow, configure the existing four keystore secrets and the public repository variable `RELEASE_CERTIFICATE_SHA256`. The workflow requires owner signing and checks this pinned fingerprint before uploading assets. It removes the temporary keystore even on failure. Do not rotate the app signer by casually replacing secrets: an installed app needs certificate continuity or a deliberately prepared Android signing lineage.

## First product key, if none exists

Create it on the owner's machine so private-key custody and recovery remain with the owner. Use a directory outside the checkout and back up the encrypted keystore and password separately. Keytool prompts for the password; do not paste it into chat or commit it.

```sh
umask 077
mkdir -p "$HOME/qubee-signing"
keytool -genkeypair -keystore "$HOME/qubee-signing/qubee-product.p12" \
  -storetype PKCS12 -alias qubee-product -keyalg RSA -keysize 4096 \
  -sigalg SHA256withRSA -validity 10000 -dname "CN=Qubee"
keytool -list -v -keystore "$HOME/qubee-signing/qubee-product.p12" -alias qubee-product
```

Keep the SHA-256 certificate fingerprint as the public pin. Before adopting a new key, compare the certificate of any already distributed APK. A new unrelated key cannot update that installation; uninstalling it would destroy local data. APK signing-key recovery and Google Play app-signing enrollment are separate owner decisions.

## Local signing of the Samsung test APK

The primary physical endpoint is the owner's Galaxy S25 Ultra. Record its actual Android API, One UI version and page size; the model name alone does not establish runtime compatibility. A second physical phone is still required for two-phone acceptance.

For Linux/macOS Bash, after creating the encrypted PKCS12 key above, enter the password interactively:

```bash
export RELEASE_KEYSTORE_FILE="$HOME/qubee-signing/qubee-product.p12"
export RELEASE_KEY_ALIAS=qubee-product
read -rsp "Keystore password: " RELEASE_KEYSTORE_PASSWORD
printf '\n'
export RELEASE_KEYSTORE_PASSWORD
export RELEASE_KEY_PASSWORD="$RELEASE_KEYSTORE_PASSWORD"
read -rp "Public certificate SHA-256 fingerprint: " QUBEE_CERT_SHA256

python3 scripts/sign_product_apk.py \
  /ABSOLUTE/PATH/Qubee-0.2.0-prekey-test-arm64.apk \
  /ABSOLUTE/PATH/qubee-owner-signed-test.apk \
  --certificate-sha256 "$QUBEE_CERT_SHA256"

unset RELEASE_KEYSTORE_PASSWORD RELEASE_KEY_PASSWORD
```

Replace both absolute path placeholders and use a fresh output filename. Run the helper from this reviewed checkout with JDK, Python 3 and Android SDK Build Tools 34.0.0 installed; set `ANDROID_HOME` to that SDK. If the signing command fails, stop before installation. Passwords are read without echo and are not embedded in shell history. The helper verifies the supplied public pin and both v2/v3 signatures before creating the final output.

This re-signs a known test APK. It does not rebuild its app/native code, raise its target API, enable calling or prove 16 KB compatibility. The previously supplied test artifact uses app/native source commit `3b1f272de4d44cf22821436d6b7ac860d4ee6dce`, min API 32 and target API 34; do not describe it as a fresh main build or a validated product release. For distribution, rebuild the reviewed source and complete the release gates.

Inspect and install only after successful signing:

```sh
"$ANDROID_HOME/build-tools/34.0.0/apksigner" verify \
  --verbose --print-certs --min-sdk-version 24 \
  /ABSOLUTE/PATH/qubee-owner-signed-test.apk
sha256sum /ABSOLUTE/PATH/qubee-owner-signed-test.apk
adb devices
adb -s SAMSUNG_ADB_SERIAL shell getprop ro.build.version.sdk
adb -s SAMSUNG_ADB_SERIAL shell getprop ro.build.version.oneui
adb -s SAMSUNG_ADB_SERIAL shell getconf PAGESIZE
adb -s SAMSUNG_ADB_SERIAL install -r /ABSOLUTE/PATH/qubee-owner-signed-test.apk
```

Use the Android SDK's platform-tools `adb`, authorize USB debugging on the phone and replace the serial placeholder. On macOS use `shasum -a 256` instead of `sha256sum`. If an existing installation has a different signing certificate, `install -r` fails; do not uninstall or clear its data to work around the mismatch. Same-signer upgrades must also use an appropriate increasing versionCode.

The APK signer only establishes artifact ownership and integrity. The S25 Ultra preflight and S0-S8 runtime acceptance remain separate; no physical gate becomes PASS from signing alone.

## Current verification status

No owner product-signing credentials were supplied for this work. Production signing remains BLOCKED until that key is available on the owner's machine or configured in the release workflow. A debug-signed R8-minified test APK is a Samsung test artifact only. No Samsung is attached to the build host; physical checks remain NOT RUN.

Record the exact source commit, APK hash, native ABI hash and signer certificate fingerprint. See [Samsung acceptance](manual-testing/samsung-android16-apk-acceptance.md). Keep release and test evidence separate and never label a debug-signed APK as a product release.

Official references: [Android app signing](https://developer.android.com/studio/publish/app-signing) and [apksigner](https://developer.android.com/tools/apksigner).
