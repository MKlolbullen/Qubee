# Qubee Android rebuild plan

This repository now contains a **clean Android shell** that deliberately ignores the older half-migrated Android layer.

## What changed

- Added a proper Android root project (`settings.gradle`, root `build.gradle`, `gradle.properties`)
- Replaced the broken `app/build.gradle` with a clean Compose-focused module config
- Added a new source set under `app/src/main/appshell/`
- Preserved the previous Android sources as reference by **not compiling them**
- Added a working Compose navigation shell with:
  - onboarding
  - conversation list
  - chat screen
  - settings screen
- Added a thin native bridge wrapper that gracefully falls back when `libqubee_crypto.so` is not packaged yet

## Why this approach

The old Android tree mixed fragments, XML layouts, Compose, missing resources, missing classes, and invalid Gradle/CMake configuration. Trying to "fix everything in place" would be slower and more brittle than creating a new compileable shell and reattaching Rust in a disciplined way.

## The current contract

The Android UI is now responsible for:

- app flow
- screen state
- local demo data
- native bridge status and graceful degradation

The Rust core should eventually own:

- identity creation/serialization
- session establishment
- message encryption/decryption
- attachment encryption
- safety-number / SAS support

## Immediate next implementation steps

1. Replace the mock `nativeCreateIdentity(displayName)` payload with a real Rust-exported identity bundle.
2. Add a durable local store (Room + encrypted local state).
3. Add relay transport and background sync.
4. Add real contact onboarding via QR invite / public bundle exchange.
