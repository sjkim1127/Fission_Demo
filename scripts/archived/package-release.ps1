param(
    [string]$Version = "",
    [string]$OutputDir = "dist",
    [switch]$SkipBuild,
    [switch]$SkipCore,
    [switch]$SkipSignatures
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-CliVersion {
    param([string]$CargoTomlPath)

    if (-not (Test-Path $CargoTomlPath)) {
        throw "Missing Cargo.toml: $CargoTomlPath"
    }

    $match = Select-String -Path $CargoTomlPath -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $match) {
        throw "Could not resolve version from: $CargoTomlPath"
    }

    return $match.Matches[0].Groups[1].Value
}

function Ensure-File {
    param([string]$PathToCheck, [string]$Message)
    if (-not (Test-Path $PathToCheck)) {
        throw "$Message ($PathToCheck)"
    }
}

function New-Sha256File {
    param([string]$ArtifactPath)

    $hash = (Get-FileHash -Path $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $line = "$hash *$([System.IO.Path]::GetFileName($ArtifactPath))"
    $shaPath = "$ArtifactPath.sha256"
    Set-Content -Path $shaPath -Value $line -Encoding ascii
    return $shaPath
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-CliVersion -CargoTomlPath (Join-Path $repoRoot "crates/fission-cli/Cargo.toml")
}

$coreZipName = "fission-demo-core-windows-x64-v$Version.zip"
$sigZipName = "fission-demo-signatures-full-v$Version.zip"

$outputRoot = Join-Path $repoRoot $OutputDir
$stagingRoot = Join-Path $repoRoot ".release"
$coreStageRoot = Join-Path $stagingRoot "core"
$sigStageRoot = Join-Path $stagingRoot "signatures"

$coreBundleDir = Join-Path $coreStageRoot "fission-demo-core-windows-x64-v$Version"
$sigBundleDir = Join-Path $sigStageRoot "fission-demo-signatures-full-v$Version"

$coreZipPath = Join-Path $outputRoot $coreZipName
$sigZipPath = Join-Path $outputRoot $sigZipName

New-Item -ItemType Directory -Force $outputRoot | Out-Null
if (Test-Path $stagingRoot) {
    Remove-Item -Recurse -Force $stagingRoot
}
New-Item -ItemType Directory -Force $coreBundleDir | Out-Null
New-Item -ItemType Directory -Force $sigBundleDir | Out-Null

if (-not $SkipBuild) {
    Write-Host "[package] Building release binary with native_decomp..."
    & cargo build --release --bin fission_cli --no-default-features --features native_decomp
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed"
    }
}

$targetReleaseDir = Join-Path $repoRoot "target/release"
$fissionCliExe = Join-Path $targetReleaseDir "fission_cli.exe"
Ensure-File -PathToCheck $fissionCliExe -Message "Missing built CLI binary"

$decompCandidates = @(
    (Join-Path $targetReleaseDir "decomp.dll"),
    (Join-Path $repoRoot "ghidra_decompiler/build/Release/decomp.dll"),
    (Join-Path $repoRoot "ghidra_decompiler/build/Debug/decomp.dll")
)
$decompDll = $decompCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $decompDll) {
    throw "Missing decomp.dll. Build native decompiler first or run cargo with native_decomp."
}

$zlibCandidates = @(
    (Join-Path $targetReleaseDir "zlib1.dll"),
    (Join-Path $targetReleaseDir "zlibd1.dll"),
    (Join-Path $repoRoot "ghidra_decompiler/build/Release/zlib1.dll"),
    (Join-Path $repoRoot "ghidra_decompiler/build/Debug/zlibd1.dll"),
    (Join-Path $repoRoot "ghidra_decompiler/build/Debug/zlib1.dll")
)
$zlibDlls = $zlibCandidates | Where-Object { Test-Path $_ } | Select-Object -Unique
if ($zlibDlls.Count -eq 0) {
    throw "Missing zlib runtime DLL (zlib1.dll or zlibd1.dll)."
}

if (-not $SkipCore) {
    Write-Host "[package] Staging core bundle..."
    $coreBinDir = Join-Path $coreBundleDir "bin"
    $coreGhidraDir = Join-Path $coreBundleDir "ghidra_decompiler"

    New-Item -ItemType Directory -Force $coreBinDir | Out-Null
    New-Item -ItemType Directory -Force $coreGhidraDir | Out-Null

    Copy-Item $fissionCliExe (Join-Path $coreBinDir "fission_cli.exe") -Force
    Copy-Item $decompDll (Join-Path $coreBinDir "decomp.dll") -Force

    foreach ($z in $zlibDlls) {
        Copy-Item $z (Join-Path $coreBinDir ([System.IO.Path]::GetFileName($z))) -Force
    }

    Ensure-File -PathToCheck (Join-Path $repoRoot "fission.toml") -Message "Missing fission.toml"
    Copy-Item (Join-Path $repoRoot "fission.toml") (Join-Path $coreBundleDir "fission.toml") -Force

    Ensure-File -PathToCheck (Join-Path $repoRoot "README.md") -Message "Missing README.md"
    Copy-Item (Join-Path $repoRoot "README.md") (Join-Path $coreBundleDir "README.md") -Force

    Ensure-File -PathToCheck (Join-Path $repoRoot "docs/runtime-guide.md") -Message "Missing docs/runtime-guide.md"
    Copy-Item (Join-Path $repoRoot "docs/runtime-guide.md") (Join-Path $coreBundleDir "RUNNING.md") -Force

    Ensure-File -PathToCheck (Join-Path $repoRoot "ghidra_decompiler/languages") -Message "Missing ghidra_decompiler/languages"
    Copy-Item (Join-Path $repoRoot "ghidra_decompiler/languages") (Join-Path $coreGhidraDir "languages") -Recurse -Force

    if (Test-Path $coreZipPath) {
        Remove-Item -Force $coreZipPath
    }
    Compress-Archive -Path $coreBundleDir -DestinationPath $coreZipPath -Force
    $coreSha = New-Sha256File -ArtifactPath $coreZipPath
    Write-Host "[package] Core zip: $coreZipPath"
    Write-Host "[package] Core sha: $coreSha"
}

if (-not $SkipSignatures) {
    Write-Host "[package] Staging signatures bundle..."
    Ensure-File -PathToCheck (Join-Path $repoRoot "signatures") -Message "Missing signatures directory"
    Copy-Item (Join-Path $repoRoot "signatures") (Join-Path $sigBundleDir "signatures") -Recurse -Force

    if (Test-Path $sigZipPath) {
        Remove-Item -Force $sigZipPath
    }
    Compress-Archive -Path $sigBundleDir -DestinationPath $sigZipPath -Force
    $sigSha = New-Sha256File -ArtifactPath $sigZipPath
    Write-Host "[package] Signatures zip: $sigZipPath"
    Write-Host "[package] Signatures sha: $sigSha"
}

Write-Host "[package] Done. Artifacts are in: $outputRoot"
