# Ghidra FFI Architecture (Fission Demo)

This document describes how native Ghidra decompilation is integrated into the demo repository through Rust FFI.

## 1. High-Level View

```text
fission_cli (Rust)
  -> fission-analysis (Rust orchestration)
    -> fission-ffi (unsafe boundary + safe wrappers)
      -> decomp.dll (C++ / Ghidra decompiler core)
        -> ghidra_decompiler/languages/*.sla (Sleigh specs)
```

Core idea:
- Rust owns CLI/analysis flow and binary metadata.
- C++ owns heavy decompilation internals.
- `fission-ffi` is the explicit safety boundary.

## 2. Crate Responsibilities

- `crates/fission-cli`
  - Demo CLI entrypoint (`fission_cli`) only.
  - One-shot command parsing and dispatch (`--info`, `--funcs`, `--decomp`, etc.).
- `crates/fission-analysis`
  - Decomp orchestration and analysis pipeline for demo runtime.
  - Interactive subsystems (`app`, `debug`, `plugin`) are gated behind `interactive_runtime`.
  - Native build orchestration for `decomp.dll` via `build.rs` when `native_decomp` is enabled.
- `crates/fission-ffi`
  - Raw extern bindings + pointer/memory safety wrappers.
  - Runtime loading and symbol bridge for decompiler + pcode optimizer hooks.
- `ghidra_decompiler`
  - Native C++ implementation and exported dynamic library (`decomp.dll` on Windows).

## 3. Build and Link Flow

Feature gate:
- `native_decomp` enables native decompiler integration.

Important build scripts:
- `crates/fission-analysis/build.rs`
  - Configures and builds `ghidra_decompiler` with CMake.
  - Auto-discovers vcpkg toolchain and zlib path on Windows.
  - Emits Rust linker search paths for `decomp`.
- `crates/fission-ffi/build.rs`
  - Adds native library search paths.
  - Copies runtime DLLs (e.g., `decomp.dll`, `zlib*.dll`) near Cargo target outputs for local run.
- `crates/fission-cli/build.rs`
  - Adds runtime search path/rpath hints when `native_decomp` is active.

Windows dependency expectation:
- `zlib` must be available (typically via vcpkg `zlib:x64-windows`).

## 4. Runtime Data Flow

At decompile request (`--decomp <addr>`):
1. CLI loads target binary using `fission-loader`.
2. Analysis layer prepares function/section/symbol context.
3. FFI layer initializes native decompiler context and registers:
   - memory blocks
   - discovered functions
   - symbols/type hints/prototypes
4. Native decompiler emits C-like output.
5. Rust post-processing applies cleanup/optimizer passes and returns final text.

## 5. Resource Resolution

Native decompilation requires Sleigh language resources:
- expected at `ghidra_decompiler/languages/`

Path resolution sources:
- `fission.toml` (`[decompiler].sla_dir`)
- `FISSION_SLA_DIR` environment variable
- fallback relative workspace detection

## 6. Packaging Contract (Demo)

For runnable native decomp in release artifacts:
- `bin/fission_cli.exe`
- `bin/decomp.dll`
- `bin/zlib*.dll`
- `ghidra_decompiler/languages/**`

These are assembled by:
- `scripts/package-release.ps1`

## 7. CI/CD Integration

Decompilation smoke coverage is provided by:
- `.github/workflows/decomp-ci.yml`
- `scripts/ci/decomp-smoke.ps1`

Smoke strategy:
- Build `fission_cli` with `native_decomp`.
- Compile a tiny C sample.
- Resolve `target_function` address from `--funcs`.
- Run `--decomp` and validate key output patterns.

## 8. Current Limitations / Notes

- Highly optimized/stripped binaries can lose friendly symbol names (`FUN_0x...`).
- Runtime native logs are verbose in current demo and may be noisy in CLI output.
- Some advanced pcode injection paths may still fall back to post-C-generation optimization in specific cases.

These are known tradeoffs for a demo-focused public reference repository.
