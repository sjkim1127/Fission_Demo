# Introduction to P-Code

## What is P-Code?

P-Code (Processor Code) is a generic intermediate representation (IR) originally developed for the Ghidra reverse engineering suite. Instead of writing analysis passes for every possible CPU architecture (x86, ARM, MIPS, PowerPC, etc.), Fission translates native instructions into P-Code.

This allows all high-level analysis—such as data flow, variable recovery, and decompilation—to be written exactly once, targeting the P-Code language.

## Design Philosophy

P-Code is designed to be extremely simple and explicit. It breaks down complex, side-effect-heavy machine instructions into micro-operations that do precisely one thing.

For example, an x86 `ADD EAX, EBX` instruction does more than just add two registers; it also updates the `EFLAGS` register based on the result. In P-Code, this is explicitly represented as multiple distinct operations.

## Address Spaces

P-Code operates natively on "Address Spaces." An address space is a contiguous array of bytes. Everything in the machine state is modeled as residing in one of these spaces:

- **RAM Space:** Represents the main memory of the process.
- **Register Space:** Represents the CPU register file. Each register (e.g., `RAX`, `RSP`) is assigned a specific offset and size within this space.
- **Unique Space:** A temporary scratchpad space used to hold intermediate values that don't correspond to physical registers or memory. These are often used when breaking down complex instructions.
- **Constant Space:** A virtual space where the offset itself is the literal constant value.

## Varnodes

The fundamental unit of data in P-Code is the **Varnode**. A Varnode is defined by three properties:

1. **Space:** The Address Space where the data lives (e.g., Register, RAM).
2. **Offset:** The byte offset within that space.
3. **Size:** The number of bytes the value occupies.

Example Varnodes:

- `(register, 0x10, 8)`: An 8-byte value starting at offset 0x10 in the register space (could represent `RAX`).
- `(ram, 0x140001000, 4)`: A 4-byte value in memory at address `0x140001000`.
- `(constant, 42, 4)`: The 32-bit integer constant `42`.

## P-Code Operations (P-Code Ops)

A P-Code instruction consists of an **Opcode**, an optional list of **Input Varnodes**, and an optional **Output Varnode**.

### Common Opcodes

- **Data Moving:**
  - `COPY`: Copies data from one Varnode to another.
  - `LOAD`: Reads data from RAM into a destination.
  - `STORE`: Writes data to RAM.

- **Arithmetic & Logic:**
  - `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`: Integer arithmetic.
  - `INT_AND`, `INT_OR`, `INT_XOR`: Bitwise operations.
  - `FLOAT_ADD`, `FLOAT_MULT`: Floating-point operations.

- **Control Flow:**
  - `BRANCH`: Unconditional jump.
  - `CBRANCH`: Conditional jump based on a boolean input Varnode.
  - `CALL`: Function call.
  - `RETURN`: Function return.

## Example Translation

Consider a simple x86_64 instruction: `MOV RAX, QWORD PTR [RCX]`

This might translate to the following P-Code:

```text
1. (unique, 0x100, 8) = LOAD (constant, RAM_ID, 4), (register, RCX_OFFSET, 8)
2. (register, RAX_OFFSET, 8) = COPY (unique, 0x100, 8)
```

By abstracting away the underlying hardware, P-Code serves as the robust foundation upon which Fission's analysis intelligence is built.
