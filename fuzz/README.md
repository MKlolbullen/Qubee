# Fuzzing the wire parsers

Coverage-guided fuzzing of every public entry point that consumes
untrusted bytes. This is the deeper counterpart to the in-CI proptest
suite in `tests/wire_parser_robustness.rs`: the proptest version runs on
every PR (bounded, no special toolchain); this runs unbounded, coverage-
guided campaigns and is meant for scheduled / manual runs.

**This crate is isolated** — the repo root is not a Cargo workspace and
`fuzz/Cargo.toml` declares its own `[workspace]`, so `cargo build` /
`cargo test` at the repo root never build it. It requires a nightly
toolchain and `cargo-fuzz`.

## Setup

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Parser under test |
|---|---|
| `parse_group_handshake` | `GroupHandshake::from_wire` (bounded-bincode handshake frames) |
| `parse_direct_message`  | `DirectMessage::from_wire` + `inspect_direct_sender` (1:1 `QUBEE_DMS`) |
| `parse_invite_link`     | `InvitePayload::from_invite_link` (`qubee://invite/...`) |
| `parse_identity_key`    | `IdentityKey::from_bytes` (direct bincode — allocation-DoS surface) |

## Run

```sh
cd fuzz
cargo +nightly fuzz run parse_group_handshake      # or any target above
cargo +nightly fuzz run parse_identity_key -- -max_total_time=300
```

Each target asserts nothing beyond "does not crash": libFuzzer treats a
panic, abort, OOM, or timeout as a finding and writes the reproducer to
`fuzz/artifacts/<target>/`. Replay one with:

```sh
cargo +nightly fuzz run parse_group_handshake fuzz/artifacts/parse_group_handshake/crash-<hash>
```

Seed corpora (optional) go in `fuzz/corpus/<target>/`; a good seed is any
valid frame captured from `tests/wire_stability.rs`.

## Note

A scheduled CI job (nightly + `cargo fuzz run -- -max_total_time=…`) is the
natural next step but is intentionally not added here — it needs its own
runner budget decision. Until then, run these before a beta cut and after
any change to a wire parser or its bincode config.
