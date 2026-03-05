# Fission Architecture Overview

Fission is a modular binary analysis framework written in Rust. The project is divided into several specialized crates to separate concerns and provide a clean, extensible API.

## Core Components

The repository structure under `crates/` includes the following main components:

### 1. `fission-core`

This is the foundational crate of the framework. It defines the core data types, traits, and error handling mechanisms used throughout the project. Other crates depend on `fission-core` to ensure a unified vocabulary across the system.

### 2. `fission-loader`

The loader subsystem is responsible for parsing executable formats (such as PE, ELF, or Mach-O). It maps the binary into virtual memory spaces, extracts sections, symbols, and segments, and prepares the memory image for further analysis or decompilation.

### 3. `fission-disasm`

This crate provides instruction decoding capabilities. Given a stream of bytes from the loaded memory image, the disassembler translates them into architecture-specific assembly instructions (e.g., x86_64, ARM).

### 4. `fission-pcode`

P-Code is the intermediate representation (IR) used by Ghidra's SLEIGH engine and Fission. This crate handles the translation of machine instructions into abstract, architecture-agnostic P-Code operations. This abstraction is crucial for performing generic binary analysis and decompilation regardless of the original processor type.

### 5. `fission-analysis`

This component implements heuristics, control flow graph (CFG) recovery, data flow tracking, and function boundary identification. It uses the information provided by the loader, disassembler, and P-Code translator to build a high-level understanding of the binary's behavior.

### 6. `fission-ffi`

This crate acts as a bridge to native implementations, particularly the Ghidra decompiler engine (`decomp.dll`). It handles the safe interop between Rust and C/C++ libraries, translating memory requests, register states, and P-Code back and forth over the FFI boundary.

### 7. `fission-signatures`

Signature matching is essential for identifying known library functions and compiler boilerplate. This crate manages the loading and application of Function ID (FID) databases, type information (TypeInfo), and custom byte patterns to enrich the analysis with semantic labels.

### 8. `fission-cli`

The frontend binary that ties all the above crates together. It provides a command-line interface for the user to invoke loading, analysis, and decompilation tasks on target executables.

## Data Flow Pipeline

A typical execution flow in Fission looks like this:

1. **Input:** `fission-cli` accepts a path to a binary file.
2. **Parsing:** `fission-loader` reads the file, identifies the format, and loads it into a virtual memory map.
3. **Exploration:** `fission-analysis` scans the memory map, using `fission-disasm` to decode instructions and find function boundaries.
4. **IR Translation:** Found functions are converted into P-Code via `fission-pcode`.
5. **Enrichment:** `fission-signatures` applies known labels and types to the recovered functions.
6. **Decompilation (Optional):** If requested, `fission-ffi` interacts with the native Ghidra decompiler to generate high-level C-like pseudocode for a given function.
7. **Output:** The gathered intelligence is printed to the terminal by `fission-cli`.
