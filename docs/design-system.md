# Qubee design system — quantum secure UI

Qubee should not look like a generic chat app with a lock icon glued on top. The visual language should communicate three things immediately:

1. **Local ownership** — keys and identity live on the device.
2. **Post-quantum security** — advanced, technical, but not academic beige.
3. **Peer-to-peer intimacy** — QR handshakes, small trusted groups, no central mothership.

## Visual direction

| Layer | Direction |
| --- | --- |
| Background | Deep-space black/blue with subtle cyan grid and radial glow. |
| Primary action | Cyan/teal, high contrast, rounded but not toy-like. |
| Secondary action | Transparent panel/button with thin cyan border. |
| Danger action | Hot red/pink, reserved for destructive key operations. |
| Panels | Glassy dark panels with 1dp cyan/blue/green quantum border. |
| Copy style | Security-aware, direct, slightly sharp. No enterprise sludge. |

## Palette

| Token | Hex | Purpose |
| --- | --- | --- |
| `Void` | `#040C16` | App background. |
| `Panel` | `#E60A1726` | Main cards/panels with alpha. |
| `PanelAlt` | `#F0102234` | Dialogs/secondary surfaces. |
| `Cyan` | `#12EAD8` | Primary action and status. |
| `Blue` | `#00A7FF` | Quantum gradient support. |
| `Green` | `#8CFF72` | PQ/secure accent. |
| `Text` | `#EAFBFF` | Primary foreground text. |
| `MutedText` | `#A3BDCA` | Secondary explanatory text. |
| `Danger` | `#FF5C7A` | Destructive actions. |

## Compose implementation

The foundation lives in:

```text
app/src/main/java/com/qubee/messenger/ui/theme/QubeeDesign.kt
```

Use this structure for new screens:

```kotlin
QubeeTheme {
    QubeeScreen {
        Column(Modifier.padding(20.dp)) {
            QubeeStatusPill("SECURE STATE")
            QubeePanel {
                Text("Title", style = MaterialTheme.typography.titleLarge)
                QubeeMutedText("Explanatory text")
                QubeePrimaryButton("Continue", onClick = { ... })
                QubeeSecondaryButton("Cancel", onClick = { ... })
            }
        }
    }
}
```

## Migration rules

- New screens should use `QubeeTheme`, `QubeeScreen`, `QubeePanel`, `QubeePrimaryButton`, `QubeeSecondaryButton`, and `QubeeStatusPill`.
- Keep raw Material components for primitives only: text fields, dialogs, snackbars, progress indicators.
- Do not hardcode random greens/blues in feature screens. Add a token to `QubeePalette` if the color is legitimate.
- Destructive key operations must use `QubeePalette.Danger` and explicit copy. No vague "Reset" buttons next to private keys. That is how footguns get polished.

## Screens migrated in this pass

- `OnboardingScreen.kt`
- `GroupInviteScreen.kt`
- `SettingsFragment.kt`

## Next UI targets

1. Chat list + empty state.
2. Conversation screen with cryptographic delivery/status indicators.
3. Contact verification screen with fingerprint comparison and QR scan.
4. Settings subpages for network bootstrap, privacy, theme and debug diagnostics.
5. Real Paparazzi baselines after the Android SDK is available.
