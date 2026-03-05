# Writing a Custom Analysis Pass

One of the main goals of Fission is to be extensible. If you want to identify a specific cryptomining algorithm, trace the usage of a specific API, or perform custom de-obfuscation, you can do so by writing an **Analysis Pass**.

This guide covers how to write a simple passive analysis pass in `fission-analysis` that traverses the P-Code of recovered functions to hunt for specific behaviors.

## The `AnalysisPass` Trait

In Fission, an analysis pass generally implements a unified trait or is registered as a callback onto the `Analyzer` context. Because the repository structure emphasizes decoupling, you have access to the fully recovered `MemoryImage`, the global `ControlFlowGraph`, and the abstracted `Function` structures.

## Example Goal: Finding `XOR` Decryption Loops

A classic pattern in malware is a simple XOR decryption loop. At the P-Code level, we want to look for blocks that contain an `INT_XOR` operation inside a loop structure.

### 1. Setting up the Pass

Create a new file (e.g., `xor_detector.rs`) within your analysis project crate.

```rust
use fission_core::function::Function;
use fission_pcode::op::Opcode;

pub struct XorDetectorPass;

impl XorDetectorPass {
    pub fn new() -> Self {
        Self {}
    }

    /// Run the pass over a specific function
    pub fn run_on_function(&mut self, func: &Function) {
        // ... implementation
    }
}
```

### 2. Iterating P-Code Operations

The `Function` struct gives you access to its constituent `BasicBlock`s, which in turn contain `PcodeInstruction`s.

```rust
impl XorDetectorPass {
    pub fn run_on_function(&mut self, func: &Function) {
        for block in func.blocks() {
            let mut found_xor = false;
            let mut found_memory_write = false;

            for pcode_inst in block.pcode_ops() {
                match pcode_inst.opcode() {
                    Opcode::INT_XOR => {
                        found_xor = true;
                    }
                    Opcode::STORE => {
                        // Writing the result back to memory is a good indicator
                        found_memory_write = true;
                    }
                    _ => {}
                }
            }

            // Primitive heuristic: Block has XOR and a STORE
            if found_xor && found_memory_write {
                // Now we need to check if this block is part of a loop
                if self.is_loop_body(func, block) {
                    println!("[!] Potential XOR Decryption loop found at {:#x}", block.start_address());
                }
            }
        }
    }
}
```

### 3. Leveraging the CFG

To check if the block is part of a loop, we query the function's internal graph edges. A loop typically involves a back-edge (an edge pointing to a block that dominates the current block, or simply an edge pointing backwards to a previously visited block).

```rust
impl XorDetectorPass {
    fn is_loop_body(&self, func: &Function, target_block: &BasicBlock) -> bool {
        let edges = func.graph().outgoing_edges(target_block.id());
        
        for edge in edges {
            let dest_block = func.graph().get_block(edge.target());
            
            // Simplistic check: Does the target's address come *before* our current address?
            // (Note: Proper dominator tree analysis is preferred for robustness)
            if dest_block.start_address() <= target_block.start_address() {
                return true;
            }
        }
        false
    }
}
```

## Running the Pass

Once your pass is implemented, you register it in your main application flow, right after the core CFG and function recovery phases have completed.

```rust
// In main.rs or lib.rs setup
let mut analyzer = Analyzer::new(&memory_image);
analyzer.recover_functions();

let mut my_pass = XorDetectorPass::new();

for func in analyzer.functions() {
    my_pass.run_on_function(func);
}
```

## Advanced Pass Features

For more complex analysis, Fission provides:

- **Use-Def Chains:** Instantly query *where* a Varnode was defined (Use-Def) and *what* instructions use a Varnode (Def-Use).
- **Data-Flow Solvers:** Propagate constants through registers to track stack frame sizes or resolve indirect calls.
- **Decompiler AST:** If absolute precision is needed, wait until `fission-ffi` has generated the high-level C AST from the Ghidra decompiler, and write your heuristic pass against the `If/While/Return` tree instead of raw P-Code.
