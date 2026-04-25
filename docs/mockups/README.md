# UI mockups

**These are hand-drawn SVG approximations of the Compose source, not
renders.** They were produced by reading the `@Composable` functions
in `app/src/main/java/com/qubee/messenger/ui/**` and translating the
visible structure into static vector art. They will diverge from the
real app the moment any of:

* the Material3 theme changes (`res/values/themes.xml`)
* a `@Composable` adds, removes, or reorders a child
* a `@SerializedName` on a model affects what text gets displayed
* the device's font scale, dark mode, or RTL setting kicks in

…and there is *no* automated check that catches the drift. Treat them
as a layout-review aid, not a source of truth.

## Replacing these with real screenshots

When you want actual fidelity, the right move is screenshot tests.
Both Paparazzi and Roborazzi work without an emulator:

```kotlin
// app/src/test/java/com/qubee/messenger/ui/OnboardingScreenshots.kt
@RunWith(TestParameterInjector::class)
class OnboardingScreenshots(
    @TestParameter device: DeviceConfig = DeviceConfig.GALAXY_S25,
) {
    @get:Rule val paparazzi = Paparazzi(deviceConfig = device)

    @Test fun onboarding_idle() = paparazzi.snapshot {
        QubeeTheme { OnboardingScreen(viewModel = fakeIdleViewModel()) {} }
    }
}
```

Then `./gradlew recordPaparazziDebug` produces deterministic PNGs in
`app/src/test/snapshots/` that you can commit alongside the code.

## What's in this directory

| file | the screen it approximates |
|------|----------------------------|
| `onboarding_idle.svg`        | First-launch identity creation, before "Create identity" is tapped. |
| `onboarding_success.svg`     | Right after `nativeCreateOnboardingBundle` returns; QR + share link visible. |
| `group_invite_default.svg`   | `GroupInviteFragment` landing — create-a-group prompt + scan/paste path. |
| `group_invite_after_scan.svg`| Same screen after scanning a peer's `qubee://invite/<token>` QR. |

## Form factor

Drawn at 360×780 dp (logical), which is what a Galaxy S25 reports to
Compose at its default font scale once the system bars are excluded.
The S25 panel is 1080×2340 px native; at 3x density that maps back to
~360×780 dp, which is what these SVGs use.
