# Local Bootstrap, TURN Strategy, and Channel Rehydration

This pass adds the missing plumbing between QR invite exchange and a survivable WebRTC path.

## What changed

- QR invite payloads now carry a deterministic bootstrap token and transport hints.
- Imported peers are registered as local-bootstrap candidates immediately after invite import.
- Local bootstrap is now a multiplexer over Wifi Direct and BLE seams.
- Offer and answer messages now include TURN policy and bootstrap token metadata.
- The WebRTC transport now supports channel rehydration with ICE restart and backoff.

## Honest caveats

Still required for a full production path:
1. Device-tested Wi-Fi Direct broadcast receiver and group-owner routing.
2. Real BLE GATT or L2CAP payload exchange in place of the current test-bus fallback.
3. Real TURN credentials from the chosen bootstrap or relay path.
4. Runtime permission UX for Nearby Wi-Fi Devices, Bluetooth Scan, Connect, Advertise, and location on older Android versions.
5. ICE restart telemetry and per-peer TURN escalation thresholds backed by metrics instead of vibes.
