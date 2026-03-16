# Real Local Bootstrap Path

This pass upgrades the local bootstrap layer from a loopback-style placeholder into actual Android transport seams that can carry WebRTC signaling on-device.

## What changed

### Wi-Fi Direct
- Added a dynamic `BroadcastReceiver` for:
  - `WIFI_P2P_STATE_CHANGED_ACTION`
  - `WIFI_P2P_PEERS_CHANGED_ACTION`
  - `WIFI_P2P_CONNECTION_CHANGED_ACTION`
- Added peer discovery and connection attempts with `WifiP2pManager.connect(...)`.
- Added group-owner endpoint resolution via `requestConnectionInfo(...)`.
- Added a real socket-based signaling server/client path over the Wi-Fi Direct group.
- Added bootstrap `hello` / `hello_ack` framing so a raw group socket can be mapped back to the intended peer handle after QR-assisted pairing.

### BLE
- Added a real GATT service with:
  - metadata characteristic
  - uplink signaling characteristic
  - downlink notify characteristic
- Added BLE advertising with a service UUID plus a hashed bootstrap-token hint.
- Added BLE scanning for that service UUID and metadata resolution back to a peer handle.
- Added an L2CAP listener/connector path for larger signaling payloads such as SDP offers and answers.
- Added chunked GATT fallback framing for cases where L2CAP is not available yet.

### Shared framing
- Added a shared wire protocol for local bootstrap payloads:
  - `hello`
  - `hello_ack`
  - `signal`
- Added bootstrap-token hashing so BLE advertisements do not emit raw bootstrap tokens.

## Important caveats
- This is still **not device-verified** in this environment.
- Wi-Fi Direct device selection is intentionally conservative and currently opportunistic; it still needs field testing in noisy nearby-peer scenarios.
- BLE L2CAP behavior varies across devices and Android versions; the GATT fallback exists because handset reality is frequently cursed.
- The new path is much more real than the previous in-memory safety net, but it still needs hardware testing for MTU, timing, permissions, and reconnection edge cases.

## Files added or heavily changed
- `WifiDirectBootstrapTransport.kt`
- `BleBootstrapTransport.kt`
- `LocalBootstrapTransport.kt`
- `BootstrapTokenHasher.kt`
- `BootstrapWireProtocol.kt`
- `AndroidManifest.xml`
