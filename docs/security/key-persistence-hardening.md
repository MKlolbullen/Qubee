# Key persistence and lock failure handling

This change retains the existing preference names, wrapping aliases, AES-GCM
format and 64-byte hex-ASCII core passphrase. It does not rotate existing keys
or change the messaging protocol.

## Enforced invariants

- All key-store operations share a process-wide lock, including first creation,
  auth-binding transitions and explicit reset. Qubee currently runs these
  components in one process; SharedPreferences is not a multi-process store.
- Newly generated secrets are returned only after a successful synchronous
  `commit()`. Ciphertext and IV are written in the same editor transaction.
- A failed/throwing commit blocks subsequent provider access across instances.
  Android can expose an updated in-memory preference map after a disk failure;
  that map is not evidence of persistence. Restart reopens the durable state.
  Explicit reset can clear the failure latch, but is destructive and is not an
  automatic recovery action.
- Partial, malformed, wrong-type and conflicting auth-bound/auth-free records
  fail closed. Auth-bound custody cannot be mistaken for first launch, and a
  missing wrapping key is not regenerated over other existing wrapped secrets.
- Disable/reset commits record changes before retiring the wrapping alias.
  Secret buffers are cleared on exceptional exits as well as successful use.
- Auth-bound custody overrides a stale Screen Lock preference. Unavailable
  authentication or a missing unlock challenge cannot advance the UI gate.
- Screen Lock transitions run on `Dispatchers.IO` and are serialized. Failed
  transitions do not publish a new setting. Other synchronous provider callers
  must use an IO worker when they can create/write secrets.

## Regression coverage

`SqlCipherKeyProviderTest` exercises real Android Keystore and encrypted
preferences, concurrent first-open through eight provider instances, partial
records, malformed lengths/types, missing keys, conflicting custody, failure
after preference publication, throwing commits, and failed disable/reset.
The fake failure adapter tests distrust of visible preference state; it is not
a real storage fault or process-kill test. `AppLockManagerTest` covers cold-start
policy, and `SettingsViewModelTest` prevents failed disable from clearing the
setting/UI state.

Run `./gradlew :app:testDebugUnitTest` and
`./gradlew :app:connectedDebugAndroidTest`. The latter needs an emulator/device.
The existing Android workflows provide build, R8 and emulator gates.

## Remaining acceptance work

- On physical devices, exercise process death/reboot immediately after first
  creation and both lock transitions; verify identity and stored messages survive.
- Exercise biometric enrollment changes, unavailable hardware, cancellation,
  invalidated wrapping keys, and low-storage/write failures. Recovery must never
  silently generate a replacement identity or report an unlocked state.
- Auth-bound enrollment still uses the existing per-use-key encryption path.
  A platform that requires an enrollment CryptoObject ceremony may reject it;
  this change keeps that failure closed. Successful enrollment/unlock and
  pre-API-30 biometric compatibility require separate device verification.
- This is cold-start/at-rest protection. The existing lock overlay clears the
  holder but does not close an already-open Room database or shut down the Rust
  core. Full live-session revocation is separate work.
- Deletion of the entire preference store is not detected as rollback. This is
  not rollback-resistant storage or a claim of hardware-backed custody on every
  device. StrongBox fallback must not be described as proven TEE protection.
- Existing Hickory dependency findings, the MobSF minimum-SDK finding and the
  physical Samsung acceptance checklist remain unresolved by this change.

Reference: [Android SharedPreferences.Editor contract](https://developer.android.com/reference/android/content/SharedPreferences.Editor).
