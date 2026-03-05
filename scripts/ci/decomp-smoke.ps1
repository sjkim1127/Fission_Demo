param(
    [string]$CliPath = "target/release/fission_cli.exe",
    [int]$MaxOutputLines = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Resolve-AbsolutePath {
    param([string]$PathValue, [string]$BaseDir)

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }

    return (Join-Path $BaseDir $PathValue)
}

function New-SmokeSource {
    param([string]$SourcePath)

    $code = @'
#include <stdio.h>
#include <stdint.h>

static int helper_mul_add(int a, int b) {
    int acc = 0;
    for (int i = 0; i < b; i++) {
        acc += a;
    }
    return acc + 7;
}

int target_function(int x) {
    int y = helper_mul_add(x, 3);
    if ((y & 1) == 0) {
        y = y / 2;
    } else {
        y = y * 5 + 1;
    }
    return y;
}

int main(void) {
    int v = target_function(11);
    printf("result=%d\n", v);
    return 0;
}
'@

    Set-Content -Path $SourcePath -Value $code -Encoding ascii
}

function Invoke-CompileWithGcc {
    param([string]$SourcePath, [string]$OutputPath)

    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
    if (-not $gcc) {
        return $false
    }

    & $gcc.Source -O0 -g -fno-inline -o $OutputPath $SourcePath
    if ($LASTEXITCODE -eq 0 -and (Test-Path $OutputPath)) {
        return $true
    }

    return $false
}

function Invoke-CompileWithClang {
    param([string]$SourcePath, [string]$OutputPath)

    $clang = Get-Command clang -ErrorAction SilentlyContinue
    if (-not $clang) {
        return $false
    }

    & $clang.Source -O0 -g -fno-inline -o $OutputPath $SourcePath
    if ($LASTEXITCODE -eq 0 -and (Test-Path $OutputPath)) {
        return $true
    }

    return $false
}

function Invoke-CompileWithMsvc {
    param([string]$SourcePath, [string]$OutputPath)

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        return $false
    }

    $vsInstall = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ([string]::IsNullOrWhiteSpace($vsInstall)) {
        return $false
    }

    $vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path $vcvars)) {
        return $false
    }

    $cmd = "`"$vcvars`" && cl /nologo /Od /Zi /GS- /Fe:`"$OutputPath`" `"$SourcePath`""
    cmd.exe /c $cmd | Out-Host
    if ($LASTEXITCODE -eq 0 -and (Test-Path $OutputPath)) {
        return $true
    }

    return $false
}

function Get-AddressFromFunctionList {
    param([string[]]$FunctionOutput, [string]$FunctionName)

    $line = $FunctionOutput | Where-Object { $_ -match "\b$FunctionName\b" } | Select-Object -First 1
    if (-not $line) {
        return ""
    }

    $m = [regex]::Match($line, "0x[0-9a-fA-F]+")
    if (-not $m.Success) {
        return ""
    }

    return $m.Value
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cli = Resolve-AbsolutePath -PathValue $CliPath -BaseDir $repoRoot

if (-not (Test-Path $cli)) {
    throw "fission_cli.exe not found at: $cli"
}

$tmpBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$workDir = Join-Path $tmpBase "fission-decomp-smoke"

if (Test-Path $workDir) {
    Remove-Item -Recurse -Force $workDir
}
New-Item -ItemType Directory -Force $workDir | Out-Null

$srcPath = Join-Path $workDir "sample.c"
$exePath = Join-Path $workDir "sample.exe"

New-SmokeSource -SourcePath $srcPath

$compiled = $false
if (-not $compiled) { $compiled = Invoke-CompileWithGcc -SourcePath $srcPath -OutputPath $exePath }
if (-not $compiled) { $compiled = Invoke-CompileWithClang -SourcePath $srcPath -OutputPath $exePath }
if (-not $compiled) { $compiled = Invoke-CompileWithMsvc -SourcePath $srcPath -OutputPath $exePath }

if (-not $compiled) {
    throw "No usable C compiler found (tried gcc, clang, cl)."
}

Write-Host "[decomp-smoke] Built C sample: $exePath"

$runtimeOutput = & $exePath
Write-Host "[decomp-smoke] Sample run: $runtimeOutput"

$funcOutput = & $cli --funcs $exePath
$addr = Get-AddressFromFunctionList -FunctionOutput $funcOutput -FunctionName "target_function"

if ([string]::IsNullOrWhiteSpace($addr)) {
    throw "Could not resolve target_function address from --funcs output."
}

Write-Host "[decomp-smoke] target_function address: $addr"

$decompOutPath = Join-Path $workDir "decomp.txt"

$decompCmd = "`"$cli`" --decomp $addr `"$exePath`" > `"$decompOutPath`" 2>&1"
cmd.exe /c $decompCmd | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Decompiler command failed with exit code: $LASTEXITCODE"
}

$decompLines = Get-Content -Path $decompOutPath
$lineCount = $decompLines.Count
$funcStart = -1
$anchors = @(
    "// Function:\s*target_function\b",
    "^\s*[A-Za-z_][A-Za-z0-9_]*\s+target_function\s*\("
)

foreach ($anchor in $anchors) {
    for ($i = 0; $i -lt $lineCount; $i++) {
        if ($decompLines[$i] -match $anchor) {
            $funcStart = $i
            break
        }
    }
    if ($funcStart -ge 0) {
        break
    }
}

if ($funcStart -ge 0) {
    $previewCount = [Math]::Min($MaxOutputLines, $lineCount - $funcStart)
    $startLine = $funcStart + 1
    Write-Host "[decomp-smoke] Decompiled function excerpt (from line $startLine, $previewCount lines):"
    $end = $funcStart + $previewCount - 1
    $decompLines[$funcStart..$end] | ForEach-Object { Write-Host $_ }
    if ($end -lt ($lineCount - 1)) {
        Write-Host "[decomp-smoke] ... output truncated. Full output: $decompOutPath"
    }
} else {
    $previewCount = [Math]::Min($lineCount, $MaxOutputLines)
    Write-Host "[decomp-smoke] Decompiled output (first $previewCount/$lineCount lines):"
    $decompLines | Select-Object -First $previewCount | ForEach-Object { Write-Host $_ }
    if ($lineCount -gt $previewCount) {
        Write-Host "[decomp-smoke] ... output truncated. Full output: $decompOutPath"
    }
}
Write-Host "[decomp-smoke] Full output file: $decompOutPath"

$decompText = $decompLines -join [Environment]::NewLine
if ($decompText -notmatch "target_function|FUN_0x" -or $decompText -notmatch "return") {
    throw "Decompiler output validation failed. Expected function body markers not found."
}

if ($decompText -notmatch "\* ?5 ?\+ ?1") {
    throw "Decompiler output validation failed. Expected arithmetic pattern '* 5 + 1' not found."
}

Write-Host "[decomp-smoke] PASS: decompilation output looks valid."
