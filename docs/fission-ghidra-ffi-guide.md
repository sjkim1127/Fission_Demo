# Ghidra Decompiler FFI Integration Guide

Fission relies on the renowned Ghidra decompiler engine to translate architecture-specific P-Code back into human-readable C-like pseudocode. However, because Fission is written in Rust and Ghidra's decompiler (`libdecomp`) is written in C++, an explicit Foreign Function Interface (FFI) boundary is required.

This guide explains the architecture of the `ghidra_decompiler` C++ component and how Fission bridges the gap in Rust via the `fission-ffi` crate.

## 1. The C++ Decompiler Architecture (`ghidra_decompiler`)

The native component is built using CMake and generates two primary targets:

- `libdecomp.dll / .so / .dylib`: The shared library exposing the C FFI.
- `fission_decomp`: A standalone CLI executable that communicates via JSON over stdin/stdout (primarily used for out-of-process isolation).

### 1.1 Layered Structure

The C++ side is logically separated into several namespaces bridging the native Ghidra API to the FFI boundary:

- **`fission::ffi`**: The outermost layer. It defines clean C functions using `extern "C"` (e.g., `decomp_create`, `decomp_load_binary`, `decomp_function`). This layer catches all C++ exceptions and translates them into safe C error codes.
- **`fission::decompiler`**: The core pipeline orchestration. It manages the `DecompilationPipeline`, executing analysis passes symmetrically (Structure analysis, Call Graph analysis, P-Code extraction).
- **`fission::analysis` & `fission::types`**: Implements custom heuristic passes natively in C++ before handing the IR to Ghidra. This includes VTable recovery, Calling Convention detection, and Type Propagation across function calls.
- **`fission::core` & `fission::loader`**: Manages the `DecompilerContext` and `MemoryImage`. It implements interfaces required by Ghidra's SLEIGH architecture to read binary bytes from sections and segment data.
- **`Ghidra libdecomp`**: The unmodified, native Ghidra C++ engine residing at the bottom.

## 2. The Rust Integration (`crates/fission-ffi`)

The `fission-ffi` crate acts as the safe Rust bridge to `libdecomp`. It abstracts away the unsafe pointer management and C memory lifecycles.

### 2.1 The Native Decompiler Context

When a user requests decompilation via the CLI (`fission_cli --decomp <addr>`), the following sequence occurs:

1. **Context Creation:** Rust calls `decomp_create()`, which allocates the heavyweight C++ `DecompilerContext`. This context holds the Sleigh specifications and global type registries.
2. **Setup:** Rust passes the `SLA` file directory (containing processor specs) via `fission.toml` configuration and the target instruction arch.
3. **Symbol & Memory Registration:** Before decompiling, Rust must tell the C++ engine what memory exists. It pushes `MemoryBlocks` (sections like `.text`, `.data`) and known symbols (from `fission-loader` and `fission-signatures`) into the native context via `decomp_add_memory_block` and `decomp_add_symbols_batch`.
4. **Decompilation Request:** Rust calls `decomp_function(ctx, address)`.
5. **C++ Execution:** The native side decodes instructions, resolves pointers against the registered memory blocks, builds the control flow graph, applies custom analysis passes (e.g., `StructureAnalyzer`), and generates the C String output.
6. **Return & Cleanup:** `decomp_function` yields a `char*`. Rust copies this into a safe `String` and immediately calls `decomp_free_string()` to prevent memory leaks across the FFI boundary.

### 2.2 Callback Architecture (Push Registration)

A unique challenge in FFI is allowing the C++ engine to request information from the Rust side (e.g., asking for dynamic symbol resolution or Rust-based P-Code optimizations).

Fetching dynamic symbols across OS platforms using standard `dlsym` is incredibly fragile. Fission solves this using **Push Registration**.

At initialization, Rust pushes C-compatible function pointers into the C++ context:

```rust
// Rust side
extern "C" fn rust_optimize_fn(json: *const c_char, len: usize) -> *mut c_char { ... }

unsafe {
    decomp_init_pcode_bridge(rust_optimize_fn, rust_free_fn);
}
```

When Ghidra reaches the P-Code optimization stage, it invokes this registered callback, passing a serialized JSON representation of the IR to Rust, allowing Rust-based analysis heuristics to modify the IR mid-flight.

## 3. Summary

Fission's architecture respects a clear separation of concerns:

- **Rust (`fission-analysis`)**: Owns the high-level orchestration, user interface, binary loading, pattern matching, and project state.
- **C++ (`ghidra_decompiler`)**: Owns the heavy lifting of SLEIGH semantic translation, native graph structurization, and AST C-code emission.

By using a clean C FFI layer, Fission combines the safety and modern ecosystem of Rust with the battle-tested decompilation maturity of Ghidra.
