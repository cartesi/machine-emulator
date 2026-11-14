## R2-DFGUESTSTATE-1

**Title.** The manual and the generated device tree declare Sv39 address translation, but every path accepts a satp
write with MODE = 9 and walks four-level Sv48 page tables

**Severity.** Medium

### Problem

The manual's section "The main processor" (doc/README.md, around line 7312) describes the processor's
address translation as: "In addition, Cartesi Machines support the Sv39 mode of address translation and memory
protection. Sv39 provides a 39-bit protected virtual address space, divided into 4KiB pages, organized by a
three-level page table." The device tree that the emulator writes into every machine says
`mmu-type = "riscv,sv39"` (src/dtb.cpp, also listed in the manual around line 8000). The RISC-V privileged
specification says of satp: "Implementations are not required to support all MODE settings, and if satp is written
with an unsupported MODE, the entire write has no effect; no fields in satp are modified."

The interpreter instead accepts MODE = 9 (Sv48): a `csrw satp` with MODE = 9 takes effect, the guest reads it back,
and address translation then performs four-level walks with 512 GiB terapages. Only Sv57 is compiled out
(`NO_SATP_MODE_SV57`). The behavior is deterministic and the same on the native and uarch paths (the Solidity step
replays the same uarch execution), so it is not a divergence between paths. It is an undocumented deviation from
the architecture the manual describes, in the address-translation area that R7 lists.

It does not threaten the goal of section 1: the satp write needs S- or M-mode, Sv48 walks are implemented as the
RISC-V specification defines them, PMA checks on physical addresses still apply, and the shipped kernel follows
the device tree and runs in Sv39. It still violates R7 ("The emulator implements the RISC-V specification and the
devices as the manual documents them, departing only where the manual documents a deviation"), and section 8 makes
the contradiction between the manual and the behavior a defect in one of the two.

The manual is not fully consistent on the point: its flash-drive notes (around lines 7493-7513) reason about "the
Sv48 address space" of the Linux kernel. Those notes describe kernel layout limits; they do not state that the
processor supports Sv48, and the processor section, the device tree and the shipped kernel's behavior all say Sv39.

### Component, role and area

The interpreter (CSR write of satp and virtual address translation), shared by the native path and the uarch
program. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". Area:
address translation (R7). The manual (doc/README.md) is the other side of the contradiction.

### Location

- src/interpret.cpp, `write_csr_satp` (around lines 2243-2262): the switch accepts `SATP_MODE_SV48`.
- src/riscv-warl.hpp, `WARL_satp` (around lines 97-110): accepts `SATP_MODE_SV48`.
- src/translate-virtual-address.hpp, `translate_virtual_address` (around lines 135-156): walks
  `mode - SATP_MODE_SV39 + 3` levels, so four for MODE = 9.
- src/riscv-constants.hpp, line 32: only `NO_SATP_MODE_SV57` is defined.
- src/dtb.cpp, line 105: `fdt.prop_string("mmu-type", "riscv,sv39")`.
- doc/README.md, "The main processor" (around lines 7306-7320).

### Evidence and test

`bugs/R2-DFGUESTSTATE-1/` contains `test.lua` (the test) and `README.md` (what it asserts and why). Run with
`bugs/run.sh R2-DFGUESTSTATE-1`; it takes under a second.

The test builds fresh 1 MiB machines in M-mode, runs `csrw satp, x5; csrr x6, satp; ld x7, 0(x8)` for 3 mcycles,
and asserts that, unless the manual's "The main processor" section mentions Sv48, a write of satp with MODE = 9
leaves satp at its previous value 0. Controls, which exit 2 if they fail: a MODE = 8 write is accepted, and a
MODE = 10 write (Sv57, compiled out) is ignored. Information lines show that after the MODE = 9 write an M-mode load
with MPRV = 1, MPP = S from VA `0x8080020000`, which only Sv48 can translate, returns the data at PA `0x80020000`
through a root-level terapage, that the same load under Sv39 raises a load page fault, and that the uarch path
(`run_uarch` and `reset_uarch` per mcycle) behaves the same. On audit/prt2 it exits 1 on every run (the reviewer ran
it three times) and prints:

```
control: write 0x8000000000080010 (Sv39) -> satp 0x8000000000080010 (accepted)
control: write 0xa000000000080010 (Sv57) -> satp 0x0000000000000000 (ignored, WARL)
probe:   write 0x9000000000080010 (Sv48) -> satp 0x9000000000080010, guest read-back 0x9000000000080010 (MODE 9)
info:    MPRV load from VA 0x8080020000 (translatable only by Sv48): loaded 0x5356343821212121 from PA 0x80020000 via a root-level terapage
info:    same load with the same table under Sv39: faulted (mcause=0xd, 13 = load page fault)
info:    uarch path: satp 0x9000000000080010, read-back 0x9000000000080010, Sv48-only load translated
manual, 'The main processor': documents Sv39 = true, documents Sv48 = false
VIOLATION: satp.MODE=9 (Sv48) write took effect (satp=0x9000000000080010), but the manual documents only Sv39 (three-level page tables) and the WARL rule requires the write to have no effect
VIOLATED: R7: address translation as the manual documents it: a write of satp with an undocumented MODE (Sv48) must have no effect unless the manual documents Sv48
run.sh: R2-DFGUESTSTATE-1: exit 1 (bug present)
```

The test exits 0 after either fix: the interpreter ignoring MODE = 9, or the manual's processor section documenting
Sv48. Its manual check is a plain search for "Sv48" in that section, so a fix of the manual must actually document
Sv48 support there. The reviewer also booted the pinned `linux.bin` (cartesi/linux v6.18.56-ctsi-1) with the
guest-tools rootfs: satp was `0x8000000000080c05` (MODE 8, Sv39) from the first sample at mcycle 5,000,000 until the
machine halted, so the shipped kernel follows the device tree and does not use Sv48. Found, proved and reviewed on
Opus 5.5; no fallback model.

### Trigger and reachability

Any guest code running in S- or M-mode that writes satp with MODE = 9. Section 4: "Any input may take control of the
firmware, the kernel, the rollup libraries, and the application. It may then run any instruction stream at any
privilege level." Section 2: "Any assignment of guest-writable memory and registers is presumed reachable." The
state is therefore reachable from any valid template. A correct guest that writes MODE = 9 is one that probes satp
modes as the RISC-V specification allows; it gets Sv48 where the manual promises it would stay in its previous mode.

### Rating

1. Out of scope: no exclusion applies. The trigger is guest code, and "The entries about applications exclude what
   an application loses, never an emulator defect that its guest triggers (R4, R5, R8)". No machine API change,
   snapshot, O1 or O2 exclusion is involved.
2. Role: the interpreter and the uarch program, "Honest operator" in the AUDIT.md table. Section 3: "The transition
   function, ... play this role in every deployment."
3. High and Medium cases: section 8 Medium, "An undocumented deterministic deviation, consistent across all paths,
   in behavior that no correct guest relies on for isolation or data integrity (R7)", together with "A contradiction
   between the manual and the behavior on a security-relevant point is a defect in one of the two. It takes the
   severity it would have if the manual were right." If the manual were right (Sv39 only), the emulator departs
   from the RISC-V specification's WARL rule for satp. The deviation is deterministic and the same on the native,
   uarch and step paths. No correct guest relies on MODE = 9 being ignored for isolation or data integrity: a guest
   that follows the manual never writes MODE = 9; one that probes modes as the specification allows gets a
   specification-conformant Sv48 with PMA checks intact; and writing satp already needs S-mode. The clause covers
   this component: it rates behavior of the transition function.
4. Critical: not reached under the preferred reading.

Two other readings give different classes.

- Critical (literal R7): R7 says that in the listed areas, address translation among them, "any deviation lets an
  input subvert a correct guest, even a deviation that is consistent across all paths". Read literally, no
  address-translation behavior is one "that no correct guest relies on", the Medium case does not fit, and step 4
  rates a violation of R7 at a reachable state Critical. What decides: whether the Medium case may judge whether a
  correct guest relies on the specific behavior, or whether R7's list settles that for the whole area.
- Low or no defect: if "support the Sv39 mode" is read as non-exhaustive, and the flash-drive notes' references to
  "the Sv48 address space" as documenting Sv48, the behavior is documented and conforms to the RISC-V specification
  (Sv48 is optional). Against this: the processor section describes only three-level tables, the device tree the
  emulator generates (and the manual lists) says `riscv,sv39`, and the shipped kernel runs Sv39.

### Possible solution and risks

Either change the interpreter or the manual, and keep the device tree consistent with the choice.

- Code: remove `SATP_MODE_SV48` from `write_csr_satp`, `WARL_satp` and `translate_virtual_address` (for example a
  `NO_SATP_MODE_SV48` guard like the Sv57 one). This changes the state transition function, so under R13 it is a new
  protocol version that must change the machine-identification registers, regenerate the uarch program, its
  pristine hash and the Solidity step. Guests that probe satp and currently use Sv48 would fall back to Sv39; the
  shipped kernel already uses Sv39. It shortens the worst-case page walk, which reduces step log size.
- Documentation: state in "The main processor" that Sv48 is supported (and Sv57 is not), and consider advertising
  `riscv,sv48` in the device tree, whose `mmu-type` binding names the largest supported mode. Changing the device
  tree changes the guest's boot trajectory (the kernel would pick Sv48), which also changes canonical hashes of new
  templates, though not the transition function.

### Risk of not fixing it

No loss of soundness or completeness: all paths agree, and the behavior is reachable only by code that already runs
in S- or M-mode. A guest or tool author who relies on the manual's Sv39-only description, or on the device tree, may
assume that a MODE = 9 write leaves satp unchanged, and get four-level translation instead. Mitigation outside the
code: treat the manual's processor section as incomplete and rely on the device tree's `mmu-type` when choosing a
mode.
