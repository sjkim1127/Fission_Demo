param(
    [string]$VendorRoot = "vendor/Fission",
    [switch]$Clean,
    [switch]$IncludeNativeDecomp,
    [switch]$IncludeSignatures
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceCratesDir = Join-Path $repoRoot (Join-Path $VendorRoot "crates")
$destCratesDir = Join-Path $repoRoot "crates"
$nativeDecompDir = Join-Path $repoRoot "ghidra_decompiler"
$signaturesDir = Join-Path $repoRoot "signatures"

$crateNames = @(
    "fission-core",
    "fission-loader",
    "fission-disasm",
    "fission-pcode",
    "fission-signatures",
    "fission-analysis",
    "fission-ffi",
    "fission-cli"
)

if (-not (Test-Path $sourceCratesDir)) {
    throw "Source crates directory not found: $sourceCratesDir"
}

New-Item -ItemType Directory -Force $destCratesDir | Out-Null

foreach ($crate in $crateNames) {
    $src = Join-Path $sourceCratesDir $crate
    $dst = Join-Path $destCratesDir $crate

    if (-not (Test-Path $src)) {
        throw "Missing source crate: $src"
    }

    if ($Clean -and (Test-Path $dst)) {
        Remove-Item -Recurse -Force $dst
    }

    Copy-Item -Path $src -Destination $dst -Recurse -Force
    Write-Host "Synced: $crate"
}

if ($IncludeNativeDecomp) {
    $srcNative = Join-Path $repoRoot (Join-Path $VendorRoot "ghidra_decompiler")
    if (-not (Test-Path $srcNative)) {
        throw "Missing native decompiler source: $srcNative"
    }

    if ($Clean -and (Test-Path $nativeDecompDir)) {
        Remove-Item -Recurse -Force $nativeDecompDir
    }

    Copy-Item -Path $srcNative -Destination $nativeDecompDir -Recurse -Force
    Write-Host "Synced: ghidra_decompiler"
}

if ($IncludeSignatures) {
    $srcSignatures = Join-Path $repoRoot (Join-Path $VendorRoot "signatures")
    if (-not (Test-Path $srcSignatures)) {
        # Legacy layout fallback
        $srcSignatures = Join-Path $repoRoot (Join-Path $VendorRoot "utils/signatures")
    }
    if (-not (Test-Path $srcSignatures)) {
        throw "Missing signatures source: expected '$VendorRoot/signatures' or '$VendorRoot/utils/signatures'"
    }

    if ($Clean -and (Test-Path $signaturesDir)) {
        Remove-Item -Recurse -Force $signaturesDir
    }

    Copy-Item -Path $srcSignatures -Destination $signaturesDir -Recurse -Force
    Write-Host "Synced: signatures"
}

Write-Host "Done. Synced demo crates into: $destCratesDir"
