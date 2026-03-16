# Alpha Vertical Slice Test Plan

This test plan defines the minimum scenarios that must pass before a private alpha is credible.

## Core scenarios

1. unlock vault and open database
2. create identity and export invite
3. import invite on second device
4. verify safety code
5. establish session
6. send and receive message over live path
7. fall back to relay when live path is unavailable
8. reconcile missed history after reconnect
9. detect peer key change and reset trust
10. wipe local state and confirm clean restart behavior

## Reliability scenarios

- process death during pending outbound message
- duplicate receipt and read-cursor replay
- same bundle re-import
- key change during active conversation
- app restart before reconciliation finishes

## Acceptance criteria

- no silent trust preservation after key change
- no duplicate message insertion after reconciliation
- no database access before unlock
- diagnostics explain current transport path and failure state
