Your goal is to optimize the Cartesi Machine Emulator,
specifically it's RISC-V interpreter.

This folder contains:
- `bench-insns.lua` per instruction benchmarks
- `bench-stress.lua` different stressing benchmarks

You can use both of them to measure emulator performance on the current machine.

You must edit only `../src/interpret.cpp` and optionally the headers it includes.
After editing it you can compile with `make -C ../src`.

Before beginning plan ahead, first you will need to study the codebase and the benchmark tools. Then create a plan, write it to `OPTIM_PLAN.md`.

Rank optimization ideas, then ask me which ones I would like you to explore (and which order), perform each experiment one by one, save findings and learnings of each experiment to `OPTIM_REPORT.md`.

Do not explore GCC tuning flags, this was already been done exhaustive and there is little gains going in that direction (unless you are absolutely sure something is off along your exploration).
Do no explore function inlining ideas, the interpreter was already optimized to perform inlining properly (unless you are absolutely sure something is off along your exploration).
Do not use git to commit changes. Although you can use git stash.
Do not spend too much time doing things I didn't approve, this experimentation will use resources (tokens, CPU time, etc).

## Tools

You can use the following tools to help optimizing.
Use when appropriate, specially the interpreter designer himself has been using this tools to optimize by hand.

But you are free to come up with new tools as needed (as long it's not complex), if you make one, make them available in this folder for future optimization explorations.

## instruction trace

Generate a x86_64 trace for given instruction:

```sh
gdb /usr/bin/lua5.4 \
    --init-command=gdbinit \
    -ex "break interpret_loop" \
    -ex "run bench-insns.lua --filter '^addi$'" \
    -ex "nstepi 1000" \
    -ex quit | tail -n 1000
```

Then you can analyze latest host instruction for `addi` instruction in this example.
Usually the latest x86_64 will be the host executed instructions to execute the guest instruction, since the `bench-insns.lua` run them in cycles, you can extract a cycle from it.

## interpret.cpp objdump

Generate a x86_64 dump for the RISC-V interpreter:
```sh
objdump -S -C -d ../src/interpret.o > interpret.cpp.objdump
```

Then you can analyze sections of `interpret.cpp.objdump` to understand the x86_64 host assembly.

## Design philosophy

Before optimizing, it is essential to understand the design philosophy of the Cartesi Machine Emulator, it's architected with the following fundamental goals:
 1. **Low complexity**, for simplifying auditing processes and minimize the potential for errors.
 2. **Determinism**, for reproducible computations across different platforms.
 3. **Portability**, for compatibility with various architectures (e.g., zkVMs, RISC-V RV32I).
 4. **Security**, for providing strong guarantees of safe and correct execution of applications.
 5. **Verifiability**, for enabling verification of state transitions during on-chain fraud proofs.

To achieve these objectives, the emulator adopts specific architectural decisions:
- **No Just-In-Time (JIT) compilation**, avoiding complexities and security issues.
- **No floating-point hardware acceleration**, as it can lead to non-deterministic results across different hardware.
- **No multi-core interpretation**, also avoiding complexity and ensuring determinism.

Those architectural decisions impact performance compared to other emulators like QEMU, which employs JIT compilation and non-deterministic optimizations.

These design philosophies cannot be violated, so do not explore optimizations against them.