# Audit remediation pass 6

This pass tightens the live native messaging path so the application stops treating preview-shell crypto as an acceptable production fallback.

## What changed

- The Android crypto engine now requires the native hybrid bootstrap path for trusted sessions.
- Preview-shell AES-GCM fallback is disabled for session creation, message encryption, and message decryption.
- The native hybrid session bootstrap now carries an initiator ratchet public key.
- The live native message path now uses a real DH ratchet on top of the hybrid bootstrap.
- Ciphertext envelopes now bind additional authenticated data to:
  - session id
  - epoch
  - message counter
  - previous chain length
  - ratchet public key
  - sender identity fingerprint
  - recipient identity fingerprint
- Hybrid sessions now support a bounded skipped-message-key cache for limited out-of-order delivery.
- Legacy classical sessions keep their stricter out-of-order behavior so older tests remain valid.

## Security outcome

This pass does not claim formal verification or production readiness, but it materially improves the live path in three important ways:

1. The trusted path is now the native hybrid path rather than a preview fallback.
2. The live path now performs DH ratchet transitions instead of only advancing a symmetric chain.
3. Replay / message-state / AAD handling is stricter and more explicit on the native path.

## Remaining work

- Compile and device-test the Rust and Android layers together.
- Quarantine or remove preview-only crypto code from production builds entirely.
- Continue relay hardening and abuse controls.
