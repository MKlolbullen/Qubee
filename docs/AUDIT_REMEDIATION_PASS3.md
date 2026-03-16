# Qubee Rust Remediation Pass 3

## Addressed in this pass

- Added the missing Rust dependencies needed by the audited modules.
- Removed the injected JavaScript from `src/storage/secure_keystore.rs` by replacing the duplicate implementation with a re-export of the canonical secure keystore.
- Replaced the hardcoded password fallback with a required `QUBEE_KEYSTORE_PASSWORD` environment variable.
- Replaced the fast BLAKE3 password KDF with Argon2id and random per-file salts.
- Replaced plaintext keystore serialization with authenticated encryption of the whole keystore blob.
- Replaced static password salt and predictable nonce generation in `src/crypto/identity.rs` with random salts and fully random 96-bit nonces.
- Fixed the `load_state()` logic so ratchet state is not zeroized before it is returned to the caller.
- Fixed the Dilithium ephemeral keypair bug in `src/secure_message.rs`, `src/file_transfer.rs`, and `src/audio.rs` so signatures are created and verified with the same keypair.
- Added a real hybrid session bootstrap path in `src/native_contract.rs` using X25519 + Kyber768 for callers that adopt the new session-init flow.
- Added bounded relay queues and bounded relay history retention to reduce unbounded memory growth.

## New native contract path

Two new functions were added:

- `create_hybrid_session_init(contact_id, peer_public_bundle_bytes)`
- `accept_hybrid_session_init(contact_id, init_bytes)`

These functions create and accept a hybrid X25519 + Kyber768 bootstrap payload that can be used to derive a post-quantum session root for the JNI/native path.

## Important compatibility note

The legacy `create_session_bundle(...)` path is still present for backwards compatibility, but it remains classical X25519-based. The Android/JNI integration must be updated to use the new hybrid bootstrap functions if the application wants the runtime session establishment path to actually use the post-quantum KEM.

## Still not fully solved in this pass

- Relay TLS is not enabled yet.
- Relay rate limiting and authenticated connection hardening are still incomplete.
- The Android layer still needs to adopt the new hybrid session-init JNI calls.
- The wider Rust tree still contains experimental modules that may need additional compile cleanup once they are brought into the active crate graph.
