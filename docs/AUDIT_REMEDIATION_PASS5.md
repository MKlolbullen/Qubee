# Audit remediation pass 5

This pass hardens the relay and demotes insecure Android fallback behavior.

## Rust relay hardening
- Added optional TLS server support to `src/bin/qubee_relay_server.rs` using `tokio-rustls`.
- Added PEM certificate/key loading via `QUBEE_RELAY_TLS_CERT_PATH` and `QUBEE_RELAY_TLS_KEY_PATH`.
- Added token-bucket rate limiting for connection bursts, pre-auth frame traffic, and authenticated frame traffic.
- Added a hard cap for text websocket frame size.
- Added rate limiter unit tests in `src/relay_security.rs`.

## Android tightening
- Native fallback is now labeled preview-only rather than secure.
- Relay authentication is disabled when the identity is not native-backed.
- Shell session algorithms are explicitly labeled `preview-shell-aes-gcm`.
- Connectivity UI now exposes a dedicated security posture panel.

## Remaining work
- TLS certificate provisioning and rotation for deployment.
- Stronger weighted rate limiting for specific relay frame types.
- Replace preview shell mode entirely once native packaging is guaranteed on all builds.
