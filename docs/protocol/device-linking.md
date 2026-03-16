# Device Linking State Model

Device linking is intentionally constrained for alpha.

## States

- `PrimaryOnly`
- `LinkPending`
- `LinkedTrusted`
- `LinkedReview`
- `Revoked`

## Rules

- each linked device must have a stable `deviceId`
- device state must be visible in the UI
- receipts and read cursors are device-aware
- a device with trust issues must not quietly inherit full trust

## Alpha limitation

For alpha, linked-device records may be derived from local and peer session state. A dedicated backend-free device issuance flow can come later.
