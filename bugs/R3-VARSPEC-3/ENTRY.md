## R3-VARSPEC-3

**Title.** The CLINT implements an active `msip` register at `0x02000000`, which sets `mip.MSIP`, but the manual says the only active CLINT addresses are `mtime` and `mtimecmp`.

**Severity.** Medium (preferred reading). Critical under a literal reading of R7's "Traps and interrupts" area. See Rating.

### Problem

The manual's `#### CLINT` section (`doc/README.md`, lines 7523-7536) reads: "The Core Local Interruptor (or CLINT)
controls the timer interrupt. The active addresses are `0x0200bff8` (`mtime`) and `0x02004000` (`mtimecmp`)." The
manual never mentions `msip` or the machine software interrupt anywhere in its prose.

The emulator has a third active CLINT register, `msip0`, at offset 0 (physical address `0x02000000`). It accepts
32-bit accesses only. A 32-bit store with bit 0 set sets `mip.MSIP` and returns `success_and_serve_interrupts`. A
store with bit 0 clear clears `mip.MSIP`. A 32-bit load returns `mip.MSIP`. If the manual were right, a store to
`0x02000000` would raise a store/AMO access fault, as a store to any other inactive CLINT offset does, and could never
make the machine software interrupt pending. The behavior is deterministic, and the native interpreter and the uarch
agree on it. This is a contradiction between the manual and the behavior in the device semantics that R7 and R8 bind
("the devices as the manual documents them"; "the guest reaches device registers only through the device semantics
that the manual specifies").

The security goal is not affected. The behavior is the same on every path, so no hash disagreement follows. As argued
under Rating, no correct guest can rely on the register being absent for isolation or data integrity. The defect is
that the specification the threat model refers to misdescribes the device's register map and the interrupts that the
device can raise.

The manual also prints a sample device tree (around line 8019). In it the CLINT node is `compatible = "riscv,clint0"`,
with `interrupts-extended = <0x01 0x03 0x01 0x07>`, which wires it to the machine software interrupt (3) as well as
the machine timer interrupt (7). Under the standard `riscv,clint0` binding, `msip` sits at offset 0. That listing is
the only place where the manual hints at the register, and it contradicts the prose.

### Component, role and area

Devices (the CLINT), the interpreter's device access path shared by the native interpreter and the uarch program.
AUDIT.md component table: "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". The
area is traps and interrupts, and device semantics (R7, R8).

### Location

- `src/clint-address-range.cpp`: `clint_csr::msip0 = 0`, `clint_read_msip` (32-bit read of `mip.MSIP`), and the
  `clint_msip0_rel_addr` case of `clint_address_range::do_write_device` (sets or clears `MIP_MSIP_MASK`; its comment
  reads "I don't yet know why Linux tries to raise MSIP when we only have a single hart").
- `doc/README.md`: `#### CLINT` (lines 7523-7536), the board table (line 7445,
  `0x02000000-0x020bffff`), and the sample device tree (lines 8019-8023).

### Evidence and test

`bugs/R3-VARSPEC-3/` contains `test.lua`, `README.md` and this entry. The guest is four hand-encoded instructions
written into RAM by the test, so no other artifact is needed beyond the in-tree emulator build. Run it with
`bugs/run.sh R3-VARSPEC-3`.

The test exits 0 in either of two cases:

- The manual's `#### CLINT` section mentions `msip`, `0x02000000` or "software interrupt".
- On both the native interpreter (`run(4)`) and the uarch (`run_uarch` and `reset_uarch` for each mcycle), the
  M-mode sequence `lui t0,0x2000; addi t1,x0,1; sw t1,0(t0)` raises a store/AMO access fault (`mcause` 7, `mtval`
  `0x02000000`) and leaves `mip.MSIP` clear.

As a control, the same store to `0x02000010`, an inactive CLINT offset, must fault that way. If it does not, the test
exits 2. On audit/prt2 the test prints:

```
manual CLINT section documents msip: false
control: store to 0x02000010 -> store access fault (mcause 7), MSIP clear
native: after 'sw 1 -> 0x02000000': mip=0x8 (MSIP=true) mcause=0x0 mtval=0x0 pc=0x8000000c
uarch : after 'sw 1 -> 0x02000000': mip=0x8 (MSIP=true) mcause=0x0 mtval=0x0 pc=0x8000000c
VIOLATED: R7 / manual '#### CLINT': the only active CLINT addresses are mtime (0x0200bff8) and mtimecmp (0x02004000); a store to 0x02000000 must fault and must not raise mip.MSIP
run.sh: R3-VARSPEC-3: exit 1 (bug present)
```

The reviewer re-ran it twice, and it exited 1 both times. Opus 5.5 found, proved and reviewed it. No fallback model
was used.

### Trigger and reachability

Any guest code with physical access to the CLINT triggers it: M-mode, or S-mode, because the emulator implements no
PMP. A single 32-bit store to `0x02000000` is enough. The state is reachable, because any guest-writable memory and
register assignment is presumed reachable. According to the code comment, the shipped Linux/OpenSBI stack already
writes this register during normal operation. No input or log from another party is needed beyond guest execution.

### Rating

1. Out of scope: no exclusion applies. No deliberate machine API state change, untrusted API caller, deployment
   violation of A1 to A8, non-template snapshot, cached hash-tree data, or unguaranteed directory is involved. The
   exclusion "Guest software that an input can subvert, as long as R7 and R8 hold" does not apply, because the
   defect is in the emulator's own device semantics, which R7 and R8 govern.
2. Role: the component is the CLINT device of the interpreter and the uarch program. In the AUDIT.md table,
   "Interpreter, state-access layers, devices, uarch program, ... | Honest operator" covers it. Section 3: "The
   transition function ... play[s] this role in every deployment."
3. High and Medium cases: the Medium case fits: "An undocumented deterministic deviation, consistent across all
   paths, in behavior that no correct guest relies on for isolation or data integrity (R7)."
   - The register is undocumented in the manual's prose.
   - The test shows it is deterministic and that native and uarch agree. The on-chain step replays the same uarch
     program.
   - No correct guest relies on the register being absent for isolation. The emulator implements no PMP, so every
     privilege level that can reach the CLINT can already write M-mode firmware memory and `mtimecmp`, and can
     already raise a machine-level interrupt. The register therefore gives no level a capability it lacks.
   - No correct guest relies on it for data integrity either. A guest that follows the manual never stores to an
     address the manual calls inactive.

   Section 8 also says: "A contradiction between the manual and the behavior on a security-relevant point ... takes
   the severity it would have if the manual were right." If the manual were right, the emulator would show exactly
   this undocumented, consistent deviation, so that clause gives the same class.
4. Critical (alternative reading): R7 says "The emulator implements the RISC-V specification and the devices as the
   manual documents them, departing only where the manual documents a deviation. ... In these areas, any deviation
   lets an input subvert a correct guest, even a deviation that is consistent across all paths. ... Traps and
   interrupts." The behavior decides whether a store traps and whether an interrupt becomes pending. If R7's list of
   areas is read as categorical, the Medium case's condition "no correct guest relies on" fails by definition. Step 4
   then applies: R7 is violated at a reachable state, and the class is Critical.

Two readings give different classes. Medium is preferred, because the facts show no isolation or data-integrity
reliance: there is no PMP, `mtimecmp` already lets the same privilege levels raise M-level interrupts, and the
shipped firmware itself relies on the register existing. Critical applies if R7's area list is categorical. A third
reading rates it Low or not a defect: the manual's sample device tree, with `riscv,clint0` and its interrupt 3 wiring,
would count as documenting a standard CLINT that includes `msip`. That reading is weaker. The listing is presented as
example output of `dtc`, not as the device's specification. The prose explicitly lists the active addresses, says
the CLINT "controls the timer interrupt", and never mentions the software interrupt. Which reading holds depends on
two things: whether R7's area list is categorical, and whether a device-tree compatible string in example output
counts as manual documentation.

### Possible solution and risks

Document the register in the manual's `#### CLINT` section. It sits at `0x02000000` (`msip`), accepts 32-bit
accesses only, a store with bit 0 set makes the machine software interrupt pending (`mip.MSIP`), a store with bit 0
clear clears it, and a load reads it. The section's opening sentence should also say that the CLINT controls the
machine software interrupt as well as the timer interrupt. This changes no transition and needs no new protocol
version.

Removing the register to match the current prose is not advisable. The code comment says the shipped Linux/OpenSBI
stack writes it, and `riscv,clint0` drivers expect it, so removal would change the transition function, need a new
machine version (R13), and likely break the guest's software interrupts.

### Risk of not fixing it

No hash, proof or claim is affected, because all paths agree. Guest developers and independent implementers, such as
a second verifier or a zk-proof of the main processor written from the manual, would implement a CLINT without `msip`.
That would diverge from the deployed transition function on every guest that touches the register, the standard
firmware included, and would break A6 for such an implementation. Until the manual is fixed, the source code
(`src/clint-address-range.cpp`) is the only specification of the register.
