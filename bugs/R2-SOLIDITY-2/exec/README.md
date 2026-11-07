# Executing the Solidity verifiers (support code for R2-SOLIDITY-1 and R2-SOLIDITY-2)

Written and run by a round 8 hunter (`DYNSOLEXEC`) to execute the pinned `machine-solidity-step` contracts. It is
support code, not a pass/fail test: `bugs/run.sh R2-SOLIDITY-2` still runs the model-based test. The orchestrator could
not re-run this harness because installing the EVM (`pip install pyrevm`) was refused by the sandbox; the results below
are the hunter's report.

Setup (what the hunter used):

1. Copy the pinned `machine-solidity-step/src/*.sol` unchanged next to `sol/Harness.sol` (into `sol/`).
2. `npm install solc@0.8.30` and run `node compile.js`. This writes `harness.json` (optimizer on, 200 runs, `shanghai`).
3. `pip install pyrevm`. `run.py` deploys the bytecode in `revm` (Cancun) and reads JSON requests on stdin.
4. Producers pipe requests into it: `lua5.4 lastleaf.lua` (the R2-SOLIDITY-2 case), `lua5.4 tlbsol.lua` (TLB-write
   steps), `edge.lua`, `reject.lua`, `bridge.lua`, `fuzz-uarch.lua`, `fuzz-send.lua`. `enc.lua` encodes a request.

Reported results: `lastleaf.lua` shows `ld` from `0xfffffffffffffff8` and `0xffffffffffffffe0` logged and verified by the
C++ code, while `UArchStep.step` reverts with `Panic(0x01)` in `Memory.validateStrideLength`. About 100k other
Solidity-versus-C++ checks matched, and about 30k mutated proofs were all rejected.
