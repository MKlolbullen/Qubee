# Qubee branding assets

Qubee's mark is an infinity loop of overlapping cyan, blue and green
ribbons with a solid cyan node at the crossing, set on a deep navy
field. The full lockup adds the `Qubee` wordmark below the mark.

## Files

| File | Purpose |
| --- | --- |
| `qubee_logo.png` | The full lockup (mark + wordmark) on its navy field, 1024×1024. Source of truth; the README header and every derived asset come from it. |
| `qubee_mark.png` | The mark alone with a transparent background, lifted from the logo at source resolution. Designed for dark surfaces: on white the glow reads as a faint halo. |
| `app/src/main/res/mipmap-*/ic_launcher_foreground.png` | Adaptive launcher foreground, 108dp canvas with the mark 64dp wide so its tips stay inside the 66dp safe circle. |
| `app/src/main/res/mipmap-*/ic_launcher_monochrome.png` | Themed-icon silhouette: the solid ribbons and node only, so it stays crisp at 48dp. |
| `app/src/main/res/drawable/ic_launcher_background.xml` | The navy gradient the mark was lifted from. |
| `app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`, `ic_launcher_round.xml` | Adaptive launcher icons wiring the three layers. |

## Regenerating

Every PNG under `app/src/main/res/mipmap-<density>/` and
`qubee_mark.png` is produced by one script; the adaptive-icon XML in
`mipmap-anydpi-v26/` and the background gradient are hand-written and
stay as they are. Replace `qubee_logo.png`, then:

```bash
python3 -m pip install pillow
python3 scripts/render_launcher_icons.py
```

The script lifts the mark off the navy by colour distance (the logo
has no alpha channel), un-premultiplies it against the per-row
background, and renders the five densities. Keep the logo's layout
(mark above, wordmark below, navy field) or adjust the band detection
in the script.

## Android sizing rules

| Use | Recommended size |
| --- | ---: |
| Small corner/status mark | 16dp - 20dp |
| Toolbar/action mark | 24dp |
| Small brand header | 32dp - 48dp |
| Onboarding/splash mark | 64dp - 96dp |
| Hero/marketing mark | 128dp+ |
| Adaptive launcher icon layer | 108dp base; important content inside roughly 66dp |
| Google Play listing icon | 512x512 PNG, no baked rounded corners |

Status-bar notification icons stay flat white silhouettes
(`ic_notification.xml`); Android tints them and discards colour.
