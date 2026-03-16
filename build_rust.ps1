# build_rust.ps1

# Stoppa scriptet om något fel inträffar
$ErrorActionPreference = "Stop"

# 1. Ställ in sökvägar
# Vi använder Join-Path för att vara säkra på att sökvägarna blir rätt i Windows
$AndroidJniDir = "app\src\main\jniLibs"

# Lista på arkitekturer vi vill bygga för
$Archs = @("arm64-v8a", "armeabi-v7a", "x86", "x86_64")

Write-Host "Förbereder mappar i $AndroidJniDir..." -ForegroundColor Cyan

# 2. Skapa mappar om de inte finns
foreach ($Arch in $Archs) {
    $Path = Join-Path $AndroidJniDir $Arch
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

Write-Host "Startar byggprocessen för Rust..." -ForegroundColor Green

# 3. Kompilera för varje arkitektur
# cargo-ndk placerar automatiskt .so-filerna i rätt undermapp när -o används

# ARM64 (Moderna telefoner)
Write-Host "Bygger för arm64-v8a..." -ForegroundColor Yellow
cargo ndk -t arm64-v8a -o $AndroidJniDir build --release
if ($LASTEXITCODE -ne 0) { Write-Error "Bygge misslyckades för arm64-v8a"; exit 1 }

# ARMv7 (Äldre telefoner)
Write-Host "Bygger för armeabi-v7a..." -ForegroundColor Yellow
cargo ndk -t armeabi-v7a -o $AndroidJniDir build --release
if ($LASTEXITCODE -ne 0) { Write-Error "Bygge misslyckades för armeabi-v7a"; exit 1 }

# x86_64 (Emulator)
Write-Host "Bygger för x86_64..." -ForegroundColor Yellow
cargo ndk -t x86_64 -o $AndroidJniDir build --release
if ($LASTEXITCODE -ne 0) { Write-Error "Bygge misslyckades för x86_64"; exit 1 }

# x86 (Äldre emulatorer - valfritt)
Write-Host "Bygger för x86..." -ForegroundColor Yellow
cargo ndk -t x86 -o $AndroidJniDir build --release
if ($LASTEXITCODE -ne 0) { Write-Error "Bygge misslyckades för x86"; exit 1 }

Write-Host "Klart! Biblioteken finns nu i $AndroidJniDir" -ForegroundColor Green