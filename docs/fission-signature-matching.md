# Signature Matching and Function Identification

Binary executables are often statically linked with standard libraries (like `libc`, `msvcrt`, or Rust's `std`). Without signature matching, the reverse engineer is presented with thousands of unnamed, recovered functions, overwhelming the analysis process.

The `fission-signatures` crate is dedicated to recognizing library code and compiler boilerplate, assigning meaningful names (like `memcpy`, `printf`, or `CRT_Startup`) so analysts can focus on the unique business logic of the binary.

## Why is identifying standard libraries difficult?

1. **Compiler Variations:** GCC, Clang, and MSVC generate vastly different machine code for the exact same source function.
2. **Optimization Levels:** A function compiled with `-O3` (size/speed optimization) looks nothing like `-O0` (debug).
3. **Relocations:** Memory addresses change, so a naive byte-for-byte hash will fail if the function references global data.

## Fission's Approach: FID (Function ID)

Fission leverages Ghidra's **Function ID (FID)** database format. FID was designed specifically to combat the issues of relocations and minor instruction variations.

### The Signature Generation Process

To understand how Fission matches a function, it helps to understand how the signature was generated in the first place:

1. **Instruction Decoding:** The target library function is disassembled.
2. **Masking:** Bytes that represent dynamic addresses (relocations, immediate values referencing memory) are "masked out" (treated as wildcards).
3. **Hashing:** The remaining stable bytes (the literal opcodes and stable register operands) are hashed together. Let's call this the *Full Hash*.
4. **Specific Hashes:** To account for functions that might have slight variations in their prologue or epilogue, sub-hashes of specific instruction windows are also taken.
5. **Database Storage:** The hashes, along with the function name and library version, are stored in a highly compressed `.fidb` file.

### The Matching Process in `fission-signatures`

When `fission-analysis` successfully recovers a new function bounding box, it asks `fission-signatures` to identify it:

1. Fission decodes the recovered function.
2. It masks the instructions according to the same rules used during database generation.
3. It generates the *Full Hash* of the function.
4. Fission queries the loaded `fidb` databases.
   - If there is an exact match with high confidence, the function is renamed immediately.
   - If there are multiple matches (hash collisions), Fission inspects the specific sub-hashes or looks at the function's call graph (does it call other known functions?) to tie-break.

## Pattern Matching (YARA-style)

Besides full function hashing, Fission also supports simple, high-speed byte pattern matching using signature files.

This is primarily used for identifying:

- **Compiler Startups:** The very first code executed before `main()` is reached. Finding the compiler startup sequence allows Fission to reliably locate `main()` without needing debug symbols.
- **Crypto Constants:** Scanning for specific S-boxes or AES constant arrays in `.rdata` to flag cryptographic algorithms.

A pattern might look like this:

```text
# MSVC 14.x Startup Pattern
PATTERN: 48 83 EC 28 E8 ?? ?? ?? ?? 48 85 C0 74 0A
```

The `??` bytes represent wildcards, allowing the pattern to match regardless of the exact address the `E8` (`CALL`) instruction points to.

## Distributing Signatures

Because FID databases cover dozens of compiler versions and standard libraries, they are massive (often gigabytes of data).
As detailed in the `fission_demo` release policy, full signature databases are **not** stored in the Git repository. They are packaged as a separate release asset (`fission-demo-signatures-full-v<version>.zip`) that users can extract into the runtime environment.
