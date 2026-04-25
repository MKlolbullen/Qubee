# Qubee R8 / ProGuard rules.

# Keep the JNI surface — entry-point names are resolved by the Rust
# shared library at runtime via `findClass(...)::nativeFoo`, so R8
# must not rename them.
-keepclasseswithmembernames class com.qubee.messenger.crypto.QubeeManager {
    native <methods>;
}
-keep class com.qubee.messenger.crypto.QubeeManager { *; }

# Hilt-generated factories rely on annotation-driven reflection.
-keep class * extends dagger.hilt.android.internal.managers.* { *; }
-keep class dagger.hilt.** { *; }

# Compose runtime classes are reflected on by tooling; the BOM keeps
# its own consumer rules but we add a safety net for our own code.
-keep class androidx.compose.** { *; }

# Gson reflective deserialization needs the model classes.
-keep class com.qubee.messenger.identity.IdentityBundle { *; }
-keep class com.qubee.messenger.groups.** { *; }
