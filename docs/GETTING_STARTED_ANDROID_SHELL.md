# Getting started with the rebuilt Android shell

## What this is

This is a **clean Compose-based Android shell** layered on top of the existing repository.
It intentionally compiles a new source set located at:

- `app/src/main/appshell/java`
- `app/src/main/appshell/res`
- `app/src/main/appshell/AndroidManifest.xml`

The older Android code is still in the repo for reference, but it is no longer part of the active build.

## Open in Android Studio

1. Open the repository root.
2. Let Android Studio import the Gradle project.
3. If Android Studio asks to create or refresh Gradle wrapper files, allow it.
4. Build and run the `app` module.

## About the Gradle wrapper

This rebuild adds proper root Gradle files, but it does **not** include a generated `gradle-wrapper.jar`, because that file is normally produced by running `gradle wrapper` in a machine that already has Gradle installed.

That means one of these paths is needed on your machine:

- open the project in Android Studio and let it manage Gradle, or
- run `gradle wrapper` locally to generate wrapper files

## Native library behavior

The app shell probes for `libqubee_crypto.so` using `System.loadLibrary("qubee_crypto")`.

- If the library is present and the exported JNI symbols match, the shell initializes the native layer.
- If not, the UI still works using a mock local identity flow.

That fallback is intentional so the Android product work can continue while the Rust/JNI contract is tightened.
