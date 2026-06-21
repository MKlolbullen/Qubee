# Qubee R8 / ProGuard rules.
#
# These only take effect in the `release` build type (minifyEnabled
# true). Debug builds and unit/instrumented tests run un-minified, so
# anything that breaks ONLY under R8 will not surface until an actual
# release build — which is why the android-smoke CI now also runs
# `assembleRelease`. Treat every block here as load-bearing.

# ---------------------------------------------------------------------
# Attributes Gson + reflection need globally.
# ---------------------------------------------------------------------
# `Signature` is mandatory for any `TypeToken<List<X>>` /
# `TypeToken<Map<..>>` — without it generic type info is erased and
# Gson throws at runtime deserialising collections (see
# `Converters.jsonToStringList` and the group-summary / member-list
# parsers). `*Annotation*` keeps `@SerializedName` readable.
# `EnclosingMethod` + `InnerClasses` keep anonymous `TypeToken`
# subclasses resolvable.
-keepattributes Signature
-keepattributes *Annotation*
-keepattributes RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations,AnnotationDefault
-keepattributes EnclosingMethod,InnerClasses

# ---------------------------------------------------------------------
# JNI surface — Rust <-> Kotlin.
# ---------------------------------------------------------------------
# Kotlin -> Rust: `external fun nativeX(...)` symbols are resolved by
# the Rust shared library by exact name; R8 must not rename them.
-keepclasseswithmembernames class com.qubee.messenger.crypto.QubeeManager {
    native <methods>;
}
-keep class com.qubee.messenger.crypto.QubeeManager { *; }

# Rust -> Kotlin: the Rust core invokes the NetworkCallback methods by
# NAME via JNI `call_method` ("onMessageReceived",
# "onGroupMessageReceived", "onMessageAcked", "onPeerLinked",
# "onPeerDiscovered"). The callback object is a `MessageService`
# instance. If R8 renames those overrides the by-name lookup fails
# silently and every inbound message / ack / peer-link is dropped in
# release builds — the single most likely first-release crash. Keep
# the interface and every implementor's methods verbatim.
-keep interface com.qubee.messenger.network.NetworkCallback { *; }
-keepclassmembers class * implements com.qubee.messenger.network.NetworkCallback {
    public <methods>;
}

# ---------------------------------------------------------------------
# Gson-reflected model classes.
# ---------------------------------------------------------------------
# Gson serialises by reflecting on field names (which become the JSON
# keys). If R8 renames the fields, JSON written by one build can't be
# read by a differently-obfuscated build — silent data loss across an
# app update, and broken JNI-boundary JSON within a build if the
# adapter and the struct disagree. Keep every package Gson touches.
-keep class com.qubee.messenger.data.model.** { *; }
-keep class com.qubee.messenger.groups.** { *; }
-keep class com.qubee.messenger.identity.** { *; }
-keep class com.qubee.messenger.crypto.EncryptedMessage { *; }
-keep class com.qubee.messenger.crypto.EncryptedFile { *; }

# Model enums are persisted by `.name` / `valueOf` through the Room
# TypeConverters. Keep their constants (the `data.model.**` keep above
# already covers them, but this is the canonical idiom and documents
# intent).
-keepclassmembers enum com.qubee.messenger.data.model.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ---------------------------------------------------------------------
# Gson runtime (defensive — modern Gson ships consumer rules, but the
# TypeAdapter machinery is reflection-heavy enough to pin explicitly).
# ---------------------------------------------------------------------
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken
-keep class com.google.gson.stream.** { *; }

# ---------------------------------------------------------------------
# Room — entities + generated implementations.
# room-runtime ships its own consumer rules, but keeping the entity
# classes is belt-and-braces given they overlap with the Gson keep.
# ---------------------------------------------------------------------
-keep @androidx.room.Entity class * { *; }
-keep class * extends androidx.room.RoomDatabase { *; }
-dontwarn androidx.room.paging.**

# ---------------------------------------------------------------------
# SQLCipher (net.zetetic) loads native code + is reflected during
# database open. Keep the package; suppress missing-class warnings for
# the optional APIs we don't call.
# ---------------------------------------------------------------------
-keep class net.zetetic.database.** { *; }
-dontwarn net.zetetic.database.**

# ---------------------------------------------------------------------
# Hilt — annotation-driven reflection on generated factories.
# ---------------------------------------------------------------------
-keep class * extends dagger.hilt.android.internal.managers.* { *; }
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }

# ---------------------------------------------------------------------
# Jetpack Compose. The BOM ships consumer rules; this is a safety net
# for our own composables. NOTE: this broad keep is conservative and
# inflates the APK — once the release build is validated end-to-end on
# hardware, narrow it to just what tooling reflects on (TODO before
# 1.0; over-keeping is safe, just larger).
# ---------------------------------------------------------------------
-keep class androidx.compose.** { *; }

# ---------------------------------------------------------------------
# ZXing embedded scanner — ships consumer rules; suppress the optional
# missing classes (it references some it doesn't bundle).
# ---------------------------------------------------------------------
-dontwarn com.google.zxing.**
-dontwarn com.journeyapps.barcodescanner.**

# ---------------------------------------------------------------------
# Keep line numbers for deobfuscatable crash reports; the
# `mapping.txt` is shipped as a release asset (see release.yml) so a
# stack trace can be symbolicated.
# ---------------------------------------------------------------------
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
