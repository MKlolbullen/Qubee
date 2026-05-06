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

### Group / chat surface (Galaxy S25 Ultra, 412×892 dp)

These five mock-ups cover the rev-3 → group-UX work end-to-end. They
sit in 460×950 SVGs that include a stylised phone bezel, status bar,
and home indicator so the proportions read as a device render.

| # | file | screen |
|---|------|--------|
| 1 | `01-inbox.svg`            | Conversations list — direct + group rows after cold-start hydration, FAB, bottom nav. |
| 2 | `02-group-chat.svg`       | Group chat (`Berlin Sec Crew`, g=4) — top bar with avatar + chevron, message bubbles, encrypted-state ribbon, composer. |
| 3 | `03-group-details.svg`    | `GroupDetailsSheet` (owner POV) — Add member, member roster with `Role` + `Remove`, "You" badge, Leave group. |
| 4 | `04-role-picker.svg`      | Role-picker `AlertDialog` — Admin (current, greyed) / Moderator / Member / Observer + Cancel. |
| 5 | `05-settings-identity.svg`| Settings → My identity — display name, fingerprint, large share-link QR, Copy + Share buttons, prefs. |

Colours match `app/src/main/java/com/qubee/messenger/ui/theme/QubeeDesign.kt`
exactly (`#040C16` Void, `#0a1726` Panel, `#102234` PanelAlt, `#12EAD8`
Cyan, `#EAFBFF` Text, `#A3BDCA` MutedText, `#FF5C7A` Danger, `#0E5F59`
MyBubble darker stop). Render in any browser, or convert to PNG with
`rsvg-convert -w 920 -o foo.png foo.svg`.

The QR code in mock-up 5 is structurally believable (three finder
patterns, alignment pattern, timing strips, brand mark in centre)
but not a scannable encoding of any real link.

### Onboarding / invite (legacy, 360×780 dp)

| file | the screen it approximates |
|------|----------------------------|
| `onboarding_idle.svg`        | First-launch identity creation, before "Create identity" is tapped. |
| `onboarding_success.svg`     | Right after `nativeCreateOnboardingBundle` returns; QR + share link visible. |
| `group_invite_default.svg`   | `GroupInviteFragment` landing — create-a-group prompt + scan/paste path. |
| `group_invite_after_scan.svg`| Same screen after scanning a peer's `qubee://invite/<token>` QR. |

## Form factor

The legacy four are drawn at 360×780 dp (default S25 reports that
once system bars are excluded). The five new group-surface mock-ups
are at 412×892 dp matching the S25 Ultra's larger 6.9″ panel
(1440×3120 px @ ~505 ppi).
