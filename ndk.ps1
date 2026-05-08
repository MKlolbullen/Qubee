# powershell
# find_and_set_ndk.ps1
$ErrorActionPreference = 'Stop'

# Candidate base folders to inspect
$Candidates = @(
    "$env:LOCALAPPDATA\Android\Sdk\ndk",
    "$env:ANDROID_SDK_ROOT\ndk",
    "$env:ANDROID_HOME\ndk",
    "C:\Android\Sdk\ndk",
    "C:\Android\ndk"
)

Write-Host "Searching for installed NDKs..." -ForegroundColor Cyan

$found = @()

foreach ($base in $Candidates) {
    if (-not [string]::IsNullOrEmpty($base) -and (Test-Path $base)) {
        Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $ndkDir = $_.FullName
            # Accept folder if it contains ndk-build.cmd or source.properties
            if ((Test-Path (Join-Path $ndkDir 'ndk-build.cmd')) -or (Test-Path (Join-Path $ndkDir 'source.properties'))) {
                $found += $ndkDir
            }
        }
    }
}

# If nothing found in common locations, do a limited recursive search under SDK root(s)
if ($found.Count -eq 0) {
    $sdkRoots = @($env:ANDROID_SDK_ROOT, $env:ANDROID_HOME, "$env:LOCALAPPDATA\Android\Sdk") | Where-Object { -not [string]::IsNullOrEmpty($_) -and (Test-Path $_) }
    foreach ($sdk in $sdkRoots) {
        Write-Host "Scanning $sdk for NDK (this may take a moment)..." -ForegroundColor Yellow
        try {
            $matches = Get-ChildItem -Path $sdk -Recurse -Directory -Depth 3 -ErrorAction SilentlyContinue |
                    Where-Object { (Test-Path (Join-Path $_.FullName 'ndk-build.cmd')) -or (Test-Path (Join-Path $_.FullName 'source.properties')) }
            $found += $matches.FullName
        } catch {
            # PowerShell older versions may not support -Depth; fall back to shallower search
            $matches = Get-ChildItem -Path $sdk -Recurse -Directory -ErrorAction SilentlyContinue |
                    Where-Object { (Test-Path (Join-Path $_.FullName 'ndk-build.cmd')) -or (Test-Path (Join-Path $_.FullName 'source.properties')) }
            $found += $matches.FullName
        }
    }
}

# Deduplicate and pick the best candidate (latest by folder name or last write time)
$found = $found | Sort-Object -Unique
if ($found.Count -eq 0) {
    Write-Error "No Android NDK installation found. Please install the NDK via SDK Manager or place it under a standard SDK path."
    exit 1
}

# Prefer semver-like folder names by sorting name desc, fallback to LastWriteTime
$best = $null
try {
    $best = $found | ForEach-Object { [PSCustomObject]@{ Path = $_; Name = Split-Path $_ -Leaf } } |
            Sort-Object { $_.Name } -Descending | Select-Object -First 1
    if (-not $best) { throw "no best" }
    $ndkPath = $best.Path
} catch {
    $ndkPath = ($found | Get-Item | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

if (-not $ndkPath) {
    Write-Error "Failed to select an NDK path from discovered candidates."
    exit 1
}

# Set for current session
$env:ANDROID_NDK_HOME = $ndkPath
Write-Host "Set ANDROID_NDK_HOME for current session to `"$ndkPath`"" -ForegroundColor Green

# Persist for the current user
# Note: setx does not update the current session; new terminals will see it.
setx ANDROID_NDK_HOME "$ndkPath" | Out-Null
Write-Host "Persisted ANDROID_NDK_HOME to user environment (use a new terminal to see it)." -ForegroundColor Green

# If you want to set system-wide, run as Administrator and uncomment:
# setx ANDROID_NDK_HOME "$ndkPath" -m

# Verify ndk-build exists
if (Test-Path (Join-Path $ndkPath 'ndk-build.cmd')) {
    Write-Host "`ndk-build.cmd` found in $ndkPath" -ForegroundColor Cyan
} else {
    Write-Host "Warning: `ndk-build.cmd` not found in $ndkPath. Some toolchains may still work, check `source.properties`." -ForegroundColor Yellow
}

Write-Host "Done." -ForegroundColor Green
