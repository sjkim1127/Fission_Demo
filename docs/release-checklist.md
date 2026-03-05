# Release Checklist (Windows x64)

## Scope Verification

- `vendor/` is ignored and not staged.
- `signatures/` is ignored and not staged.
- `target/` and `ghidra_decompiler/build/` are ignored.
- Root workflows `.github/workflows/decomp-ci.yml` and `.github/workflows/release-tag.yml` exist and are enabled.

## Build Verification

Run from repository root:

```powershell
cargo metadata --format-version 1 --no-deps
cargo build --release --bin fission_cli
cargo build --release --bin fission_cli --no-default-features --features native_decomp
```

Expected:

- Metadata command succeeds.
- Both build commands succeed.

## Runtime Smoke Test

Use a local test binary (example: `C:/Windows/System32/notepad.exe`):

```powershell
./target/release/fission_cli.exe --info C:/Windows/System32/notepad.exe
./target/release/fission_cli.exe --funcs C:/Windows/System32/notepad.exe
./target/release/fission_cli.exe --decomp 0x1400019b0 C:/Windows/System32/notepad.exe
```

Expected:

- All commands exit `0`.
- `--decomp` command runs with native runtime available.

## Interface Reduction Verification

- Confirm only one binary target exists for demo CLI:

```powershell
cargo metadata --format-version 1 --no-deps | Select-String 'fission_tui|ffi_test|"name":"fission"'
```

Expected:

- No matches for removed binaries (`fission`, `fission_tui`, `ffi_test`).

- Confirm removed options are not exposed:

```powershell
./target/release/fission_cli.exe --help
```

Expected:

- Help output does not include `--cfg`, `--graph`, `--decomp-all`.

## Packaging

Create both release assets:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package-release.ps1
```

Expected artifacts under `dist/`:

- `fission-demo-core-windows-x64-v<version>.zip`
- `fission-demo-core-windows-x64-v<version>.zip.sha256`
- `fission-demo-signatures-full-v<version>.zip`
- `fission-demo-signatures-full-v<version>.zip.sha256`

## Asset Validation

- Core zip contains:
  - `bin/fission_cli.exe`
  - `bin/decomp.dll`
  - `bin/zlib*.dll`
  - `ghidra_decompiler/languages/**`
  - `fission.toml`
- Signatures zip contains:
  - `signatures/fid/**`
  - `signatures/fidb_java/**`
  - `signatures/typeinfo/**`
  - `signatures/die/**`
  - `signatures/patterns/**`
- SHA256 files match actual zip hashes.

## Install Verification

1. Core-only install:
- Unzip core package.
- Run `bin/fission_cli.exe --info <binary>` and `--funcs <binary>`.

2. Core + signatures install:
- Unzip signatures package so folder becomes `./signatures` next to core root.
- Run `--decomp` and verify signature loading logs show at least `signatures/fid` path usage.
- Verify `signatures/typeinfo/**` exists in the signatures zip (asset validation step).

## CI/CD Automation

- Native decompilation smoke is executed on GitHub Actions:
  - Workflow: `.github/workflows/decomp-ci.yml`
  - Script: `scripts/ci/decomp-smoke.ps1`
- Tag-based release packaging/upload is executed on GitHub Actions:
  - Workflow: `.github/workflows/release-tag.yml`
  - Trigger: push tag `v*.*.*`
  - If `signatures/` is not present in CI, workflow falls back to core-only packaging.
