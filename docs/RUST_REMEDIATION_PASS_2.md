# Rust Remediation Pass 2

This pass hardens two weak areas from the previous review:

1. native session lifecycle enforcement around the chain-key model
2. explicit relay recovery semantics for key rotation and device re-link

## Native session lifecycle

The native session model now carries an explicit lifecycle state:

- `active`
- `rekey_required`
- `relink_required`
- `closed`

The chain-key model is still intentionally simpler than a full double ratchet, but the session now behaves like a real state machine instead of a bag of counters.

### What changed

- sessions serialize and restore their lifecycle state and epoch
- gap detection marks a session as `rekey_required`
- remote identity change can mark a session as `relink_required`
- chain exhaustion now blocks further message processing until rotation
- session rotation resets counters, advances the epoch, and reactivates the session

### What this improves

- makes failure modes explicit instead of ad hoc
- makes Android-side recovery logic easier to reason about
- prevents continued traffic after session continuity has already broken

## Relay key rotation

Authenticated clients can now rotate the key material for their existing handle/device binding through an explicit relay frame.

### Flow

1. client authenticates with current binding
2. client sends `key_rotation_request`
3. relay verifies the new bundle matches claimed handle/device/fingerprint
4. relay updates the binding and broadcasts `key_rotation_applied`

This is a real protocol transition instead of an implicit server-side overwrite.

## Relay device re-link

A binding conflict no longer ends as a generic rejection wall.

### Flow

1. conflicting device authenticates and proves possession of the new key
2. relay returns `binding_conflict` with a `relinkToken`
3. an authenticated sibling device for the same handle sends `approve_device_relink`
4. relay replaces the binding and emits `device_relink_applied`
5. the pending client can retry authentication using the approved new binding

This turns binding conflict into a reviewable recovery path.

## What is still not done

This is still not a full Signal-style double ratchet.

Still missing:

- skipped-message handling
- post-compromise security
- automatic peer-driven ratchet step negotiation
- persistent relay-side namespace governance
- peer notification fanout for key changes beyond currently connected same-handle devices

The code is substantially less naive than before, but the honest claim is still: improved session discipline and relay recovery semantics, not protocol completion.
