# Control Flow Graph (CFG) Recovery

One of the most critical steps in binary analysis is figuring out the execution flow of the program. This process is handled primarily in the `fission-analysis` crate, utilizing both the disassembler (`fission-disasm`) and the P-Code translator (`fission-pcode`).

## What is a CFG?

A Control Flow Graph (CFG) is a directed graph where:

- **Nodes (Vertices):** Represent Basic Blocks.
- **Edges:** Represent the flow of control (jumps, branches, calls, fall-throughs) between the Basic Blocks.

### Basic Blocks

A **Basic Block** is a sequence of instructions with:

1. One single entry point (no jumps *into* the middle of the block).
2. One single exit point (the block ends with a branch, return, or fall-through to the next block).
Once execution enters a basic block, it is guaranteed to execute completely from top to bottom before branching elsewhere.

## CFG Recovery Process in Fission

Fission performs CFG recovery using a recursive descent approach, heavily relying on the semantics provided by P-Code.

### Step 1: Entry Point Discovery

The recovery algorithm needs a place to start. A typical binary has several known entry points:

- The main program Entry Point (extracted from `fission-loader`).
- Exported functions (e.g., in DLLs or shared objects).
- Init/Fini arrays (constructors/destructors registered by the compiler).

### Step 2: Linear Disassembly & Basic Block Formation

Starting from an entry point, `fission-disasm` begins disassembling instructions sequentially.
Fission simultaneously translates these instructions into P-Code. It looks specifically for P-Code operations that alter control flow:

- `BRANCH` (Unconditional Jump)
- `CBRANCH` (Conditional Jump)
- `CALL` (Function Call)
- `RETURN` (Return from function)

When one of these control flow operations is encountered, the current basic block is terminated.

### Step 3: Edge Resolution and Recursive Descent

When a block is terminated, Fission evaluates the target of the branch.

1. **Direct Branches (`BRANCH`, `CALL` to a constant address):**
   Fission adds the target address to its "to-visit" queue. The target address marks the beginning of a new Basic Block. An edge is added to the graph linking the current block to the target block.

2. **Conditional Branches (`CBRANCH`):**
   Fission adds *two* implicit targets to the queue:
   - The branch target address (if the condition is true).
   - The fall-through address (the instruction immediately following the `CBRANCH`).

3. **Indirect Branches (`BRANCHIND`, `CALLIND`):**
   These are branches to an address stored in a register or memory location (e.g., `JMP RAX` or `CALL [RBP-0x10]`).
   *This is where CFG recovery becomes difficult.* `fission-analysis` uses data-flow tracking (Value Set Analysis) over the P-Code to attempt to resolve the possible values of the register. If it cannot be resolved (e.g., a complex jump table), the CFG may remain incomplete until further analysis passes resolve the targets.

### Step 4: Iteration

The algorithm pops addresses off the "to-visit" queue, disassembles them, forms new basic blocks, and discovers new edges. This process repeats until the queue is empty.

## Heuristics and Fallbacks

Because standard recursive descent misses functions that are never called directly (or only called via unresolved function pointers), Fission employs heuristic passes after the primary recovery:

- **Prologue Scanning:** Scanning unallocated memory gaps for known function prologue byte patterns (e.g., `55 48 89 E5` for `push rbp; mov rbp, rsp` on x64).
- **Code Pointer Scanning:** Scanning `.data` and `.rdata` sections for values that look like valid pointers into the `.text` section, and treating them as potential entry points.
