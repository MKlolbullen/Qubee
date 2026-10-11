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

## Current verification status

No owner product-signing credentials were supplied for this work. Production signing remains BLOCKED until that key is available on the owner's machine or configured in the release workflow. A debug-signed R8-minified test APK is a Samsung test artifact only. No Samsung is attached to the build host; physical checks remain NOT RUN.

Record the exact source commit, APK hash, native ABI hash and signer certificate fingerprint. See [Samsung acceptance](manual-testing/samsung-android16-apk-acceptance.md). Keep release and test evidence separate and never label a debug-signed APK as a product release.

Official references: [Android app signing](https://developer.android.com/studio/publish/app-signing) and [apksigner](https://developer.android.com/tools/apksigner).
