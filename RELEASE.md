# Releasing Qubee

Step-by-step procedure for cutting a versioned, signed APK release.
Assumes the build infrastructure landed in
`.github/workflows/release.yml` is already wired (it is, as of
`9c09e8b`).

## One-time setup (per maintainer)

You only do this once per person who'll be cutting releases. The
keystore + passwords stay on your local machine and in GitHub
Secrets; nothing keystore-y is ever committed.

### 1. Generate the release keystore

```bash
keytool -genkey -v -keystore qubee-release.jks \
        -alias qubee \
        -keyalg RSA -keysize 4096 \
        -validity 10950 \
        -storetype PKCS12
```

`-validity 10950` is 30 years. Android requires the signing
certificate to outlive the app; rotating signing keys is a
[Play App Signing](https://developer.android.com/studio/publish/app-signing#app-signing-google-play)
operation we don't yet support, so generate it long.

`keytool` prompts for:
* a keystore password (call this `KEYSTORE_PASSWORD`),
* a key password (call this `KEY_PASSWORD` — *can* equal the
  keystore password but conventionally differs),
* the certificate's CN / OU / O / L / ST / C fields. None of these
  are user-visible; they're embedded in the cert. "Qubee Maintainer"
  / "Qubee" / your country code is fine.

Verify it:

```bash
keytool -list -v -keystore qubee-release.jks -alias qubee
```

The fingerprint shown here is the one users see when they install;
publish it in `SECURITY.md` so users can verify out-of-band that
nothing has been compromised.

### 2. Encode the keystore for GitHub Secrets

GitHub Secrets accept text only, so the binary keystore goes in
base64:

```bash
base64 -w0 qubee-release.jks > qubee-release.jks.b64
```

`*.jks` and `*.jks.b64` are in `.gitignore` — neither file should
ever land in git. Keep both files in a secure local location
(password manager, encrypted vault, hardware key — your choice;
just not in this repo or any other).

### 3. Add the four GitHub Secrets

In `Settings → Secrets and variables → Actions → New repository secret`,
add:

| Secret | Value |
|--------|-------|
| `RELEASE_KEYSTORE_BASE64` | contents of `qubee-release.jks.b64` (one line, no trailing newline) |
| `RELEASE_KEYSTORE_PASSWORD` | the keystore password from step 1 |
| `RELEASE_KEY_ALIAS` | `qubee` (or whatever `-alias` you used) |
| `RELEASE_KEY_PASSWORD` | the key password from step 1 |

The release workflow reads all four. Missing any of them aborts
the build at the "Decode release keystore" step with a clear error
message.

### 4. Verify the workflow can see the secrets

Trigger a manual dispatch run with a fake tag input — the workflow
will fail at the build step (no real tag exists yet) but if the
"Decode release keystore" step succeeds you know the secrets are
visible.

```bash
gh workflow run release.yml --ref main -f tag=v0.0.0-test
gh run watch
```

Cancel the run after the keystore step finishes.

## Cutting a release

### 1. Confirm the changelog

`CHANGELOG.md` should already have a `## [<version>]` section for
the version you're tagging. If not, add it as a separate commit
*before* tagging. The release workflow extracts this section as the
GitHub Release body.

### 2. Run the local sanity checks

```bash
cargo test --no-fail-fast               # 73 green
cargo build --features _typecheck_jni   # JNI typecheck clean
./build_rust.sh                          # cross-compile all 4 ABIs (optional locally)
```

### 3. Tag and push

```bash
version=0.1.0-alpha
git tag -a v$version -m "v$version"
git push origin v$version
```

The push triggers `.github/workflows/release.yml`. It runs end-to-
end in ~12-15 minutes:

1. Resolves `versionName` from the tag
2. Computes `versionCode` from `git rev-list --count HEAD`
3. Cross-compiles `libqubee_crypto.so` for arm64-v8a /
   armeabi-v7a / x86_64 / x86
4. Decodes the keystore from secrets, signs `:app:assembleRelease`
5. Verifies the signature with `apksigner verify --verbose`
6. Computes SHA256 + collects the ProGuard mapping
7. Creates the GitHub Release with `qubee-<version>.apk` +
   `.sha256` + mapping attached

### 4. Verify the released APK

Once the workflow finishes:

```bash
gh release view v$version
gh release download v$version --pattern '*.apk' --pattern '*.sha256'
sha256sum -c qubee-$version.apk.sha256        # must match
apksigner verify --verbose qubee-$version.apk # must report "v2 / v3 scheme: true"
```

### 5. Smoke-test on hardware

Sideload onto an arm64 Android 7.0+ device:

```bash
adb install qubee-$version.apk
```

Confirm:
* Onboarding screen loads (creates a local identity).
* Inbox tab is empty on a fresh install.
* Settings → My identity shows fingerprint + share-link QR.
* Generating an invite from a second device + scanning it brings
  the contact into the address book.
* Long-press → Verify launches the verification screen, fingerprint
  + SAS render, "Verify" / "Codes match" persists `VERIFIED`.
* Sending a message round-trips between two devices.

Document any regressions in a `v<version>.x` follow-up.

## Hotfix releases

For a `v<version>.1` patch release:

1. Branch off the existing tag: `git checkout -b release/v$version.1 v$version`.
2. Cherry-pick or write the fix; update `CHANGELOG.md` with a new
   `[<version>.1]` section.
3. Tag and push as in step 3 above.

Don't roll forward versions silently — `versionCode` is monotonic
per tag (computed from `git rev-list --count HEAD`), so a hotfix
on a side branch produces a *lower* `versionCode` than `main`. Make
sure the hotfix branch has at least one commit ahead of the parent
tag, or pass `-PqubeeVersionCode=<n>` explicitly via
`workflow_dispatch` to override.

## Rotating the signing key

This is **not yet supported**. We don't ship Play App Signing
upgrade keys, so a key rotation today would require every user to
uninstall + reinstall — same friction as a full forge. Tracked for
post-1.0.

If the current key is compromised:

1. Cut the new keystore as in "One-time setup".
2. Update the four GitHub Secrets.
3. Bump the major version (the new APK won't install over the old
   one anyway because the signing certificates differ).
4. Publish the new fingerprint in `SECURITY.md` and the GitHub
   Release notes; advise users to uninstall the old version.

## Release checklist

A copy-pasteable checklist for the final review before tagging:

- [ ] `cargo test` passes locally
- [ ] `cargo build --features _typecheck_jni` clean
- [ ] `cargo audit --deny unsound --deny yanked` clean
- [ ] `CHANGELOG.md` has a `## [<version>]` entry
- [ ] `SECURITY.md` reflects current state
- [ ] No uncommitted changes on the tag commit (`git status` clean)
- [ ] `app/build.gradle` `versionName` default still reasonable
      (the workflow overrides it; this is the local-build fallback)
- [ ] Keystore + secrets verified per "Verify the workflow can see
      the secrets" above
- [ ] Smoke-test plan in `docs/two-device-walkthrough.md` is current
- [ ] Tag is annotated (`git tag -a`, not lightweight)
