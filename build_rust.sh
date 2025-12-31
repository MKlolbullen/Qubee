#!/bin/bash
set -e # Avbryt om något kommando misslyckas

# 1. Ställ in sökvägar
# Ändra denna om din app-mapp heter något annat
ANDROID_JNI_DIR="app/src/main/jniLibs"

# 2. Skapa mappar för arkitekturerna i Android-projektet
mkdir -p "$ANDROID_JNI_DIR/arm64-v8a"
mkdir -p "$ANDROID_JNI_DIR/armeabi-v7a"
mkdir -p "$ANDROID_JNI_DIR/x86"
mkdir -p "$ANDROID_JNI_DIR/x86_64"

echo "Bygger Rust-bibliotek för Android..."

# 3. Kompilera för varje arkitektur och kopiera .so-filen
# Vi döper om filen till libqubee_crypto.so om den inte redan heter det
# (Cargo skapar lib[name].so baserat på namnet i Cargo.toml)

# ARM64 (Moderna telefoner)
cargo ndk -t arm64-v8a -o "$ANDROID_JNI_DIR" build --release

# ARMv7 (Äldre telefoner)
cargo ndk -t armeabi-v7a -o "$ANDROID_JNI_DIR" build --release

# x86_64 (Emulator)
cargo ndk -t x86_64 -o "$ANDROID_JNI_DIR" build --release

# x86 (Äldre emulatorer - valfritt)
cargo ndk -t x86 -o "$ANDROID_JNI_DIR" build --release

echo "Klart! Biblioteken ligger nu i $ANDROID_JNI_DIR"
