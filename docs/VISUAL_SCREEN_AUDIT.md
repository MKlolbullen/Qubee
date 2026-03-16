# Visual screen audit

This pass focuses on making the Android Compose shell easier to verify visually and less fake in the places where the UI was previously bluffing.

## Route inventory

All user-facing routes declared in `QubeeApp.kt` currently have a corresponding screen implementation:

- `onboarding` → `OnboardingScreen.kt`
- `conversations` → `ConversationsScreen.kt`
- `invite` → `InviteScreen.kt`
- `chat/{conversationId}` → `ChatScreen.kt`
- `trust/{conversationId}` → `TrustDetailsScreen.kt`
- `settings` → `SettingsScreen.kt`
- `linked-devices` → `LinkedDevicesScreen.kt`
- `connectivity` → `ConnectivityScreen.kt`
- `danger-zone` → `DangerZoneScreen.kt`

The unlock gate is also implemented through `UnlockScreen.kt` before the navigation host is shown.

## What changed in this pass

- Added a reusable QB brand mark / lockup in Compose so the app now carries the project identity instead of only generic text.
- Inserted the QB branding in the app bar and in the major first-touch flows:
  - unlock
  - onboarding
  - conversations
  - invite
  - settings
- Added a preview catalog (`ui/preview/QubeeScreenCatalog.kt`) with sample data for every major screen so Android Studio can render the whole visual surface map without needing a live backend or device state.
- Removed one misleading UI affordance:
  - the linked-devices screen previously had a no-op “Add linked device” button
  - it now explicitly communicates that the enrollment flow is staged next and keeps the CTA disabled
- Fixed settings cards so chevrons only appear on items that actually navigate.

## Honest limitations

This repository snapshot does not include a Gradle wrapper, and this container does not have a full Android SDK / emulator stack wired for real runtime verification. That means this audit is structural and source-level, not a final “built and tapped every pixel on-device” claim. Anything stronger would be clown math.

## Recommended local verification

1. Open the project in Android Studio.
2. Use the Compose preview catalog to sanity-check all screens quickly.
3. Run the app and verify these flows end-to-end:
   - unlock
   - onboarding
   - conversation list
   - invite import/share
   - chat → trust details
   - settings → linked devices / connectivity / danger zone
4. Replace the generated Compose glyph with a final exported asset later if you want pixel-perfect parity with the marketing logo.
