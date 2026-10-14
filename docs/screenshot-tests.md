# Compose screenshot tests

This project uses [Paparazzi] for deterministic, JVM-side screenshot
tests of Compose surfaces. Paparazzi runs in plain `./gradlew test`
— **no emulator, no device, no Android Studio plugin**. Snapshots are
PNGs committed under `app/src/test/snapshots/`; CI diffs against them
on every push.

[Paparazzi]: https://cashapp.github.io/paparazzi/

## Running

```bash
# Generate / overwrite the baseline PNGs:
./gradlew :app:recordPaparazziDebug

# Diff current code against committed baselines (CI default):
./gradlew :app:verifyPaparazziDebug
```

A failing `verify` produces `app/build/paparazzi/failures/<test-name>.png`
side-by-side with the baseline so the visual diff is obvious.

## Why this exists

The hand-drawn SVGs in `docs/mockups/` are commentary that drifts
silently. Screenshot tests pin the actual output of the actual
Composables — the moment a theme color shifts or a row of text moves
2dp, the diff lights up. Use both: SVGs for early design discussion,
Paparazzi for shipped UI.

## Writing a new screenshot test

Tests live under `app/src/test/` (NOT `androidTest/` — Paparazzi is
JVM-only). Pattern:

```kotlin
class FooScreenshotTest {
    @get:Rule
    val paparazzi = paparazziRule() // the Galaxy S25 Ultra profile, see ScreenshotTestSupport.kt

    @Test fun foo_default_state() = paparazzi.snapshot {
        QubeeTheme { FooScreenContent(state = FooState()) }
    }
}
```

The Composable under test must be **stateless** — it should take its
state as a parameter. Composables that pull from Hilt-injected
ViewModels need a small refactor to expose a stateless rendering
function. The pattern:

```kotlin
@Composable fun FooScreen(viewModel: FooViewModel) {
    val state by viewModel.state.collectAsState()
    FooScreenContent(state, onAction = viewModel::onAction)
}

@Composable fun FooScreenContent(state: FooState, onAction: (Action) -> Unit) {
    // ...all the actual layout code lives here
}
```

`FooScreenContent` is what the test calls.

## Device config

The reference phone is a Galaxy S25 Ultra. `GALAXY_S25_ULTRA` in
`ScreenshotTestSupport.kt` is a custom `DeviceConfig` for it:
3120x1440 at 498 ppi, rendered at 560 dpi (3.5x), so every screen
lays out at 411x891 dp, the same as on the phone. `paparazziRule()`
uses it; every baseline is recorded on it so a theme change shows up
as one consistent diff. For other form factors Paparazzi ships
`DeviceConfig.NEXUS_5` (small phone), `PIXEL_5`, `PIXEL_6_PRO` (large
phone) and `NEXUS_7_2012` (tablet), or construct a `DeviceConfig`
with explicit `screenWidth`, `screenHeight` and `density`.

## CI integration

Add the verify task to your CI pipeline after lint + unit tests:

```yaml
- run: ./gradlew :app:verifyPaparazziDebug
- if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: paparazzi-failures
    path: app/build/paparazzi/failures/
```

The artifact upload is what makes a CI failure debuggable — without it
you only see "diff exceeded threshold" with no idea what changed.
