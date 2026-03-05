# Fission binary Loader Guide

The loader component (`fission-loader`) is the very first stage in the Fission analysis pipeline. Its primary job is to take a raw binary file from disk and map it into a virtual memory representation, recreating how the operating system would load the file into memory at runtime.

## Core Responsibilities

1. **Format Identification:** Determine the executable format (e.g., Portable Executable (PE) for Windows, ELF for Linux/Unix).
2. **Metadata Extraction:** Parse headers and directories to extract global information like the entry point, architecture, and image base.
3. **Section Mapping:** Read the sections (text, data, rdata, bss) and segments from the file and map them to their corresponding Virtual Addresses (VAs).
4. **Symbol Resolution:** Parse export tables, import tables, and debug symbols to attach names to specific memory addresses.
5. **Relocation Application (Optional/Partial):** Understand how the binary might be relocated if it's not loaded at its preferred base address.

## The Memory Image

The ultimate output of the loader is a unified **Memory Image**. This is an abstract structure that provides a cohesive view of the entire address space.

Instead of the rest of the Fission framework worrying about file offsets and PE headers, they simply query the Memory Image:

- "What byte is at virtual address `0x140001005`?"
- "Is the address `0x140002000` executable or read-only?"

### Address Spaces & Blocks

The Memory Image is composed of multiple contiguous **Memory Blocks**. Each block corresponds roughly to a section in the binary. A block tracks:

- **Base Address:** Where it starts in the virtual address space.
- **Size:** Its length in bytes.
- **Permissions:** Read, Write, and Execute (RWX) flags.
- **Backing Data:** The actual bytes. For uninitialized segments (like `.bss`), the backing data might be represented logically as zeros without allocating full physical memory.

## The API Surface

The `fission-loader` provides traits that abstract away the specifics of PE or ELF files.

### `BinaryLoader` Trait

The common interface for all loaders. It requires implementors to expose:

- `fn entry_point(&self) -> u64;`
- `fn architecture(&self) -> Architecture;`
- `fn sections(&self) -> Vec<SectionView>;`
- `fn imports(&self) -> Vec<ImportSymbol>;`
- `fn exports(&self) -> Vec<ExportSymbol>;`

### Example Workflow

```rust
use fission_loader::{pe::PeLoader, BinaryLoader};
use std::fs;

// 1. Read raw bytes from disk
let raw_bytes = fs::read("target_app.exe").unwrap();

// 2. Instantiate the appropriate loader
let mut loader = PeLoader::new(&raw_bytes).expect("Failed to parse PE");

// 3. Extract intel
let entry = loader.entry_point();
println!("Entry point: {:#x}", entry);

// 4. Generate the Memory Image for downstream use
let mem_image = loader.build_memory_image();
```

## Challenges in Loading

Writing a robust loader is notoriously difficult due to:

- **Malformed Binaries:** Obfuscators and packers deliberately break headers in ways that the OS loader tolerates but standard parsers choke on.
- **Architecture Quirks:** Endless variations in relocation types and thread-local storage (TLS) implementations.
- **Undocumented Features:** Relying on precise OS loader behaviors that are not officially specified.

Fission's loader aims to be resilient to corrupted headers while maintaining enough fidelity for accurate static analysis.
