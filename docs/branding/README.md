# Qubee branding assets

Qubee's current mark is a post-quantum themed **Q + bee + key** symbol:

- the circular body reads as a capital `Q`,
- the tail resolves into a subtle bee abdomen,
- the stinger becomes a small key to signal secure messaging,
- the cyan/teal/green palette gives the app a quantum/security identity without falling into generic blue-lock boredom.

## Files

| File | Purpose |
| --- | --- |
| `qubee_mark_master.svg` | Source-of-truth scalable logo mark for Figma/Inkscape/Illustrator refinement. |
| `app/src/main/res/drawable/ic_qubee_mark.xml` | Android VectorDrawable fallback for in-app use and themed launcher icon support. |
| `app/src/main/res/drawable/ic_launcher_background.xml` | Deep-space adaptive launcher background. |
| `app/src/main/res/drawable/ic_launcher_foreground.xml` | Inset adaptive launcher foreground using the vector mark. |
| `app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` | Adaptive launcher icon. |
| `app/src/main/res/mipmap-anydpi-v26/ic_launcher_round.xml` | Round adaptive launcher icon. |

## Android sizing rules

Use vector/dp sizes in UI and only export PNGs when a target actually needs raster artwork.

| Use | Recommended size |
| --- | ---: |
| Small corner/status mark | 16dp - 20dp |
| Toolbar/action mark | 24dp |
| Small brand header | 32dp - 48dp |
| Onboarding/splash mark | 64dp - 96dp |
| Hero/marketing mark | 128dp+ |
| Legacy launcher icon | 48dp base (`48/72/96/144/192px` across mdpi..xxxhdpi) |
| Adaptive launcher icon layer | 108dp base; keep important content inside roughly 66dp |
| Google Play listing icon | 512x512 PNG, no baked rounded corners |

## Production note

The Android VectorDrawable is intentionally simplified. Android's vector format does not reproduce SVG filters/glow perfectly, so the high-fidelity glow should be exported as PNG foreground layers from the SVG/Figma source once the final silhouette is locked.

Recommended final workflow:

```text
Figma/Inkscape master SVG
  -> Android VectorDrawable fallback
  -> Adaptive icon PNG foreground/background exports
  -> Play Store 512x512 PNG
  -> README/app screenshots
```

Avoid committing generated PNG piles until the mark is stable. They are easy to regenerate and noisy in diffs.
