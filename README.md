# Fission Demo (Public Repo + Split Release Assets)

This project is a demo of Fission, which is currently under development.  
Much of the code has been intentionally trimmed, and the demo is designed as a learning/forking reference focused on the Ghidra FFI integration architecture.

- LinkedIn: https://www.linkedin.com/in/sung-joo-kim-718a93303/
- Discord: https://discord.gg/yPYkCrwKzc

This repository is a publishable Fission demo source tree.

## Project Status

- This demo is intentionally scoped down from the private/main Fission codebase.
- Primary goal: educational reference for the native Ghidra FFI integration architecture.
- Primary runtime target: Windows x64 (`fission_cli` one-shot workflow).

### Current Limitations

- The decompiler FFI logic is not fully complete yet.
- It has not been extensively tested against real-world binaries, diverse edge cases, or heavily obfuscated binaries.

## Decompilation Quality Test (local)

I performed a local decompilation test using the provided `tests/test_binary.exe` to verify the `fission_cli` one-shot decompile workflow.

- Command used:

  ``
  target\release\fission_cli.exe tests\test_binary.exe --decomp 0x140001440 --output tests\decomp_encrypt.c --profile quality --verbose
  ``

- Outcome:
  - The native decompiler initialized and ran, but the process exited with code 1 before producing a stable decompiled C file in `tests/`.
  - Captured full console output (including native decompiler logs) to `tests/decomp_encrypt_all.txt` for debugging.

- Actions taken:
  - Fixed a CLI bug where fallback decompilation code path ignored `--output` (patched `crates/fission-cli/src/cli/oneshot/decompile.rs`).
  - Rebuilt `fission-cli` and re-ran the test; the native decompiler still exited with code 1 during this run.

- Next steps (suggested):
  - Investigate native decompiler failure (check `ghidra_decompiler` files and FID database compatibility) or run under a debugger to capture the native stack trace.
  - If you want, I can continue debugging the native exit or open an issue with collected logs.

Files produced during testing:
- `tests/decomp_encrypt_all.txt` — full console log capture
- `crates/fission-cli/src/cli/oneshot/decompile.rs` — small patch to respect `--output` when writing fallback decompilation


## Quick Start

```powershell
cargo build --release --bin fission_cli --no-default-features --features native_decomp
./target/release/fission_cli.exe --info <path-to-binary>
./target/release/fission_cli.exe --funcs <path-to-binary>
./target/release/fission_cli.exe --decomp <address> <path-to-binary>
```

## CLI Behavior (Demo)

- `fission_cli` is a one-shot CLI only in this demo build.
- Interactive/TUI modes are removed from the public demo scope.
- Running `fission_cli.exe` without arguments exits after showing usage.
- This is expected behavior (double-click launch will appear to close immediately).

Use it from a terminal:

```powershell
./bin/fission_cli.exe --help
./bin/fission_cli.exe <path-to-binary> --info
./bin/fission_cli.exe <path-to-binary> --funcs
./bin/fission_cli.exe <path-to-binary> --decomp 0x140001000
```

## Policy Summary

- Public repo stays lightweight: source + docs + scripts.
- Full signatures are not committed to repo; they are distributed as a release asset.
- Release format is split zip assets:
  - `core` zip
  - `signatures` zip
- Windows x64 is the primary release target.

## Scope: Repository vs Release Assets

### Public repository includes

- Root scaffold: `Cargo.toml`, `README.md`, `fission.toml`, `.gitignore`
- Demo crates under `crates/`
- Scripts under `scripts/`
- `ghidra_decompiler` source and `languages/` (but not `build/`)
- Docs under `docs/`

### Public repository excludes

- `vendor/`
- `signatures/` data files (release assets only)
- `target/`, `ghidra_decompiler/build/`
- Sensitive local files (`.env*`, `*.key`, `*.pem`, `*.pfx`)

### Release assets include

1. `fission-demo-core-windows-x64-v<version>.zip`
- `bin/fission_cli.exe`
- `bin/decomp.dll`
- required `bin/zlib*.dll`
- `ghidra_decompiler/languages/**`
- `fission.toml`, `README.md`

2. `fission-demo-signatures-full-v<version>.zip`
- `signatures/fid/**`
- `signatures/fidb_java/**`
- `signatures/typeinfo/**`
- `signatures/die/**`
- `signatures/patterns/**`

Each zip is generated with a matching `.sha256` file.

## Copy-Based Source Sync (from local vendor)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sync-demo-from-vendor.ps1 -Clean
```

Optional sync targets:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/sync-demo-from-vendor.ps1 -Clean -IncludeNativeDecomp
powershell -ExecutionPolicy Bypass -File scripts/sync-demo-from-vendor.ps1 -Clean -IncludeSignatures
powershell -ExecutionPolicy Bypass -File scripts/sync-demo-from-vendor.ps1 -Clean -IncludeNativeDecomp -IncludeSignatures
```

## Local Build

Demo build target is `fission_cli` only.

Default:

```powershell
cargo build --release --bin fission_cli
```

Native decomp build:

```powershell
cargo build --release --bin fission_cli --no-default-features --features native_decomp
```

## Package Release Assets

Generate core + signatures zip artifacts:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package-release.ps1
```

Optional arguments:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package-release.ps1 -Version 0.1.0
powershell -ExecutionPolicy Bypass -File scripts/package-release.ps1 -SkipBuild
powershell -ExecutionPolicy Bypass -File scripts/package-release.ps1 -SkipSignatures
```

Artifacts are written to `dist/`.

## Install Guide

### Core only

1. Unzip `fission-demo-core-windows-x64-v<version>.zip`.
2. Run:

```powershell
./bin/fission_cli.exe --info <path-to-your-binary>
./bin/fission_cli.exe --funcs <path-to-your-binary>
```

### Core + Signatures

1. Install core package.
2. Unzip `fission-demo-signatures-full-v<version>.zip` so that `signatures/` sits next to core root.
3. Run:

```powershell
./bin/fission_cli.exe --decomp <addr> <path-to-your-binary>
```

## Release Checklist

See [docs/release-checklist.md](docs/release-checklist.md).

## CI/CD

- Native decompilation smoke test is automated in:
  - `.github/workflows/decomp-ci.yml`
  - `scripts/ci/decomp-smoke.ps1`
- Tag-based release packaging and asset upload is automated in:
  - `.github/workflows/release-tag.yml`
  - Trigger: `git tag vX.Y.Z && git push origin vX.Y.Z`
  - If `signatures/` is missing in CI, workflow publishes core assets only.

## Architecture Docs

- Ghidra FFI architecture: [docs/ghidra-ffi-architecture.md](docs/ghidra-ffi-architecture.md)
