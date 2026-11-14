## R1-R10-1

**Title.** The uarch-step verifiers (the regenerated machine-solidity-step and the C++ replay) accept uarch stores to
the PMA array, the shadow TLB, HTIF and `uarch_x0`. The native uarch refuses these stores as uarch traps.

**Severity.** High

### Problem

The native uarch refuses a uarch store (`sd`/`sw`/`sh`/`sb`) whose physical address falls in a range that the uarch
may not write. Examples are the PMA array, the shadow TLB, HTIF MMIO, read-only or unknown shadow slots, and the uarch
`x0` shadow word. `log_step_uarch` throws for such a store, so the step has no successor. In THREAT_MODEL.md that is a
uarch trap: "The uarch traps when it executes [...] an access that its memory map does not allow" (R3).

The uarch-step verifiers do not perform these checks. The regenerated machine-solidity-step implements a uarch store
as a plain word write in the Merkle tree. So does the C++ replay behind `machine::verify_step_uarch`. Both check only
that the logged address equals the computed address and that the Merkle proof matches. They then accept the log and
define a successor state in which the protected word has been overwritten.

The log authenticates the store address. `rs1` comes from a logged and authenticated register read, and the
immediate comes from the logged instruction word. The protocol constants fix the meaning of each of these addresses:
the board map in doc/README.md and the uarch shadow table. So the log "already authenticates the condition", and R3
requires the verifier to refuse it. Accepting it gives a successor to a state that the state transition function says
has none. It also makes the referee verifier disagree with the honest operator's log producer, which R2 forbids.

The defect does not break the goal of section 1 by itself. The before-states that trigger it need non-pristine uarch
registers or uarch RAM, which no valid template reaches (see reachability). What it removes is a margin. The referee
would accept a fabricated uarch step that overwrites the PMA entries, the shadow TLB or other protected state, if any
other defect ever made such a before-state agreed or reachable.

### Component, role and area

- `machine-solidity-step` v0.17.0-test1 regenerated from `audit/prt2`. AUDIT.md role: **Referee verifier**. Area:
  uarch-step verification of stores, in `UArchStep.sol` (`executeSD`/`SW`/`SH`/`SB` through `writeUint*`), which calls
  `EmulatorCompat.writeWord`, which calls `AccessLogs.writeWord`. Dave's `CartesiStateTransition` calls it and
  inherits the defect. Under section 3 that inheritance is rated by the copy's role.
- The C++ replay `uarch_replay_state_access` (`machine::verify_step_uarch`). Role: **Support**, under "Off-chain
  verifiers (the C, Lua and JSON-RPC verify functions)".
- Shared source: `src/uarch-step.cpp`, from which both are translated or compiled, has no memory-map check on stores
  (`writeUint64`/`32`/`16`/`8` call `writeWord`). The only native check is in `machine::write_word`, and the
  verifiers never execute it.

### Location

- `bugs/harness/work/solidity-step/step/src/EmulatorCompat.sol`, `writeWord` (line ~127).
- `bugs/harness/work/solidity-step/step/src/AccessLogs.sol`, `writeWord` (line ~146).
- `src/uarch-replay-state-access.hpp`: `do_write_word` (line ~358) and `check_write_word_access` (line ~259).
- For comparison, the native refusal: `src/machine.cpp`, `machine::write_word` (lines 2030-2075). It is reached
  through `src/uarch-state-access.hpp` `do_write_word` and `src/uarch-record-state-access.hpp` `do_write_word`.
- `src/uarch-step.cpp`, `writeUint64`/`writeUint32`/`writeUint16`/`writeUint8` (lines ~69-115).

### Evidence and test

`bugs/R1-R10-1/` contains `test.lua` (the test), `README.md` (what it asserts and the expected output) and this
entry. Run it with `bugs/run.sh R1-R10-1`. It takes about 3 s. It needs the in-tree emulator, the harness config
`baremetal-minimal`, foundry (`anvil`, `cast`), `jq`, and the StepVerifier artifact built by the shared EVM harness
(`bugs/harness/work/evm/out`).

For each case, the test loads `baremetal-minimal` and writes `sd rs2, imm(rs1)` at uarch RAM 0x600000. It sets
`uarch_pc` = 0x600000 and the source and base registers. It then checks that the native `log_step_uarch` refuses the
step. Next it hand-builds the step log in the access order of `src/uarch-step.cpp`, with every access carrying Merkle
proofs of the before-state. It requires both of these to reject that log:

- the regenerated `StepVerifier.step`. The test installs its runtime code with `anvil_setCode` on a private anvil, on
  a random port in 20000-29999, and stops that anvil at the end.
- `cartesi.machine:verify_step_uarch`.

A control store to uarch RAM 0x600100 must be accepted by the native uarch and by both verifiers, all with the same
after-hash. This validates the log crafting. If the control fails, the test exits 2.

On audit/prt2, the test exits 1 and prints:

```
control: uarch RAM 0x600100        native: ok | C++ verify: accepted (= native) | EVM step: accepted (= native)
PMA array (0x10000)                native: TRAP (attempted memory write to read-only PMAs at address 0x10000(65536))
                                     C++ verify_step_uarch: ACCEPTED, after-hash 7bff4949b4df...b2b8508397e
                                     EVM StepVerifier.step: ACCEPTED, after-hash 7bff4949b4df...b2b8508397e
shadow TLB (0x1000)                native: TRAP (attempted memory word write to protected memory range shadow state at )
                                     C++ verify_step_uarch: ACCEPTED, after-hash 700bad410769...87d5a190c8a
                                     EVM StepVerifier.step: ACCEPTED, after-hash 700bad410769...87d5a190c8a
HTIF tohost (0x40008000)           native: TRAP (attempted memory write to HTIF device at address 0x40008000(1073774592)
                                     C++ verify_step_uarch: ACCEPTED, after-hash 10be391cfc97...30ed40f84c7dbf
                                     EVM StepVerifier.step: ACCEPTED, after-hash 10be391cfc97...30ed40f84c7dbf
uarch x0 shadow word (0x400018)    native: TRAP (register is read-only)
                                     C++ verify_step_uarch: ACCEPTED, after-hash e852b4251bd0...cfe4693568ecbd
                                     EVM StepVerifier.step: ACCEPTED, after-hash e852b4251bd0...cfe4693568ecbd
VIOLATED: R3: a verifier refuses a uarch trap whenever its log already authenticates the condition (uarch stores to
fixed protocol addresses that the uarch memory map does not allow); 8 acceptance(s) of 8
run.sh: R1-R10-1: exit 1 (bug present)
```

(The hashes are abbreviated here. The test prints them in full.)

The reviewer re-ran the test three times with exit 1 and identical output. One more run during a host disk-full
episode exited 2 (harness error), which is unrelated to the defect. Once both verifiers refuse these stores, the
trap cases count 0 acceptances and the test exits 0. The test changes no audited code.

Other variants of the same root cause, not exercised by the test:

- The verifiers also accept stores that the native refuses to read-only shadow registers such as `mvendorid`,
  `marchid` and `mimpid`.
- They accept stores to unknown shadow slots, such as the revert-root-hash word.
- They accept stores to the sentinel above every range.
- They accept stores to gaps of the uarch-state node.

### Trigger and reachability

A dishonest claimant in a uarch-level match would need the verifier to start from a before-state whose uarch is about
to execute such a store. It would then submit a hand-built log, which "Logs and proofs are adversarial" (section 4)
allows.

No input sequence from any valid template produces such a before-state:

- Every mcycle starts from the pristine uarch. A valid template has "the uarch in its pristine reset state", and every
  mcycle ends with the uarch reset. So the uarch registers and uarch RAM at any reachable position are those that the
  pristine program produces from a reachable main state.
- The guest cannot alter the uarch state. R8 says "Guest memory accesses cannot address [...] the uarch state and
  uarch memory".
- The pristine program issues stores only through `uarch_bridge_state_access`:
  - shadow-register writes through `bridge_write_reg`;
  - TLB writes through the dedicated `write_tlb` ecall, which the verifiers check;
  - memory-word writes (`do_write_memory_word`), which the interpreter performs only after its PMA lookup has found a
    writable memory range.
- The PMA array, the shadow ranges and HTIF are not writable memory in the PMA entries. Those entries are fixed at
  creation and read-only to the guest (R8). HTIF writes are emulated by updating the `htif_*` shadow registers.
- Hence the pristine program never stores to these addresses from a reachable state.

If it ever did, the native uarch would trap from a reachable state. R3 calls that Critical, but it would be a separate
defect in the uarch program, not this one.

### Rating

1. Out of scope: no. The trigger is a crafted log that a dishonest claimant submits to a referee verifier. Section 4
   says "Logs and proofs are adversarial. A verifier must assume that every count, index, address, size, and hash it
   receives was chosen to fool it." No exclusion of section 8 applies:
   - It does not need an untrusted party to call the machine API. The test uses the API only to build the before-state
     and the proofs.
   - It does not need a deployment that violates one of A1 to A8.
   - It does not need a snapshot that the emulator did not write.
2. Role: the regenerated machine-solidity-step is a **Referee verifier** (AUDIT.md: "`machine-solidity-step`
   v0.17.0-test1, with its generated code and constants regenerated from `audit/prt2` | Referee verifier"). Section 3
   defines that role as "A verifier whose acceptance settles disputes, such as the on-chain verifiers". This clause
   covers the Solidity step. The C++ `verify_step_uarch` is Support ("Off-chain verifiers (the C, Lua and JSON-RPC
   verify functions) | Support"). It shares the defect, but the referee role is the most critical one, so it decides.
3. High and Medium cases: High. Section 8 High lists "A verifier that misbehaves only on demonstrably unreachable
   before-states. Misbehaving means [...] accepting a wrong or second after-hash (such as accepting a uarch trap, R3)."
   R3 requires "A verifier refuses a trap whenever the log it receives already authenticates the condition". Here the
   trap condition is decided by the store address, which comes from authenticated log data, together with protocol
   constants (R10: "A verifier may depend on the referee parameters, on the constants of its protocol version, and on
   the authenticated log data"). The before-states are unreachable for the reasons given above. Both clauses cover a
   referee verifier, which is this component's role.
4. Critical: not reached. Critical would require the pristine uarch to execute such a store from a reachable state,
   and none is known.

Two readings. Doc/README.md says "code running in the uarch has access to the entire state of the Cartesi Machine"
and "In addition to being able to access all memory ranges and devices visible to the main processor, the uarch
includes a private 2MiB of RAM". It does not define the uarch memory map precisely.

- Reading A, preferred: the native `machine::write_word` is the uarch memory map. Then these stores are uarch traps
  and the verifiers are wrong. The class is High, as a referee verifier, and the test asserts the right behavior.
  Supporting facts:
  - The manual calls the uarch shadow "read-only".
  - The uarch writes the TLB only through a dedicated ecall that the verifiers check.
  - The log producers refuse these stores.
  - R3 defines traps by what the uarch memory map allows.
- Reading B: if the manual meant that the uarch may store anywhere as a plain word write, the defect would sit in the
  native uarch and its log producers. They would then be refusing steps that the referee accepts. That is a divergence
  between paths (R2), and also High: "A divergence between paths only at demonstrably unreachable states", in the
  honest-operator role. Under B, a correct fix would make the native accept, and this test would keep failing.

Either reading gives High. The fact that would decide between them is the maintainers' statement of the uarch memory
map.

### Possible solution and risks

Make the verifiers check the store's address before accepting it.

- In `uarch_replay_state_access::do_write_word` and in the Solidity step (`EmulatorCompat.writeWord`, or the
  `writeUint*` helpers of the generated `UArchStep.sol`), refuse every address in a range that the native
  `machine::write_word` refuses. That covers:
  - the PMA array and the shadow TLB;
  - device ranges (CLINT, HTIF, PLIC);
  - unknown or read-only slots of the processor shadow and the uarch shadow, including `uarch_x0`;
  - addresses outside every range.
  Implement this as an allow-list of the writable shadow slots plus the uarch RAM, plus a deny-list of the
  fixed-layout ranges.
- Alternatively, move the check into `src/uarch-step.cpp`, for example as a `require` on the store address, so that
  the native, record, replay and generated Solidity paths share one definition.

Risks:

- The fix changes the accesses and the acceptance of the uarch-step verifier, which is part of the protocol (R13).
  It needs a new protocol version and consistent regeneration of the step (A6).
- The check must not refuse any store that the pristine uarch performs from a reachable state. Otherwise it would
  break R4 completeness. Examples to keep allowed:
  - writable shadow registers;
  - flash drives and other memory ranges whose addresses vary by configuration. For these the verifier cannot decide
    from constants alone, so the check should be limited to the fixed-layout ranges.
- Gas cost per store rises slightly.

### Risk of not fixing it

A deployed referee accepts a fabricated successor for uarch states that should have none. That successor can rewrite
the PMA entries, the shadow TLB, `uarch_x0` or other protected state. Today this is exploitable only from before-states
that no valid template reaches. The goal still holds, but a margin is gone. Any future defect that lets a dishonest
claimant get such a before-state agreed, or makes the pristine uarch reach one, would turn into an accepted wrong
transition. The trigger is any dishonest claimant in a uarch-level match. No mitigation outside the code is known,
other than keeping the before-state agreed as A1 requires.
