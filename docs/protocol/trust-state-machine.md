# Trust State Machine

Trust is explicit, observable, and revocable.

## States

- `Unverified`
- `Verified`
- `ResetRequired`
- `Blocked`

## Events

- `LocalVerified`
- `LocalReset`
- `PeerFingerprintObserved(same=true)`
- `PeerFingerprintObserved(same=false)`
- `BlockPeer`
- `AllowAfterReset`

## Transition rules

- unverified + local verification -> verified
- verified + same fingerprint observation -> verified
- verified + changed fingerprint observation -> reset required
- reset required + local verification -> verified
- any state + block -> blocked
- blocked + local reset -> unverified

## Requirements

- key changes must never preserve `Verified`
- UI warning must be triggered when entering `ResetRequired`
- active session must be invalidated when entering `ResetRequired`
