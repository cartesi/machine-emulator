## R3-VARSPEC-1

**Title.** The bit layout that the manual gives for the first word of a PMA entry (R/W/X/IR/IW positions, an `E` bit, a 4-bit `DID` at bits 11-8) does not match the encoding the emulator writes into the guest-readable PMA array.

**Severity.** Medium (preferred reading). Critical under a literal reading of R7's "any deviation" in "Address translation and memory permissions" (see Rating).

### Problem

`doc/README.md`, section "PMAs", documents each PMA entry as two 64-bit words at `0x10000` that "are readable both
internally and externally", and gives the first word as

| Bits  | 63-12   | 11-8 | 7  | 6  | 5 | 4 | 3 | 2 | 1  | 0 |
|-------|---------|------|----|----|---|---|---|---|----|---|
| Field | start   | DID  | IW | IR | X | W | R | E | IO | M |

with "The `M`, `IO`, and `E` bits are mutually exclusive". The emulator packs the word as `M`=0, `IO`=1, `R`=2,
`W`=3, `X`=4, `IR`=5, `IW`=6, `DID`=11-7 (5 bits), and has no `E` bit. Every attribute other than `M` and `IO` sits at
a different position than the manual says. A guest that decodes the PMA array as the manual documents gets wrong
attributes for every range. Every entry appears to have `E` set together with `M` or `IO`. RAM appears to have
`DID` 0 (empty). The read-only flash drive appears not readable but executable, with `DID` 1. The rx buffer appears
not readable but executable, with `DID` 3 (flash drive).

The permissions the emulator enforces are the configured ones. The interpreter, the uarch program (compiled from the
same headers) and every other path decode the array with the same constants. So the deviation is deterministic and
consistent across paths, and does not change any hash or proof. It contradicts the manual's description of the state
layout, which R13 makes part of the transition function, and of guest-visible state that R7 says must follow the
manual. It does not threaten the goal of section 1: no path disagrees, and enforcement of the permissions is correct.

### Component, role and area

The interpreter state layout: the PMA array written at machine creation and read by the interpreter and the uarch
program. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". The other
side of the contradiction is the manual (`doc/README.md`, "PMAs"), which either the code or the manual must change to
match.

### Location

- `src/pmas-constants.hpp`, `enum PMA_ISTART_shifts` and `enum PMA_ISTART_masks` (`M`=0, `IO`=1, `R`=2, `W`=3, `X`=4,
  `IR`=5, `IW`=6, `DID_SHIFT`=7, `DID_MASK`=`31 << 7`, no `E`).
- `src/pmas.hpp`, `pmas_pack_istart` and `pmas_unpack_istart`, which use those constants.
- `doc/README.md`, section "PMAs" (about lines 7894-7943), the first-word table and the sentence on `M`/`IO`/`E`.

### Evidence and test

`bugs/R3-VARSPEC-1/` contains `test.lua` (the test), `README.md` (what it asserts) and this entry. Run
`bugs/run.sh R3-VARSPEC-1` (about 1 s). The test builds a machine with 1 MiB of RAM and a read-only flash drive at
`0x100000000`. An M-mode guest loads the `istart` word of the first 12 PMA entries from `0x10000`, once natively and
once through the uarch (one `run_uarch`/`reset_uarch` per mcycle). The test requires the two runs and `read_word` to
agree (otherwise exit 2). It parses the first-word table from `doc/README.md` and decodes each word with it. It then
requires that no entry has more than one of `M`, `IO`, `E`. It also requires RAM to decode as `M`=1, `E`=0, `R`=`W`=`X`=1,
`DID`=1, the read-only flash drive as `M`=1, `E`=0, `R`=1, `W`=`X`=0, `DID`=3, and the rx buffer as `M`=1, `E`=0,
`R`=1, `W`=`X`=0, `DID`=7. Those are the attributes and DID values the manual and `src/pmas-defines.h` give for these
ranges.

On audit/prt2 it exits 1 on every run (re-run three times by the reviewer). It prints
`manual PMA first-word layout: DID=11-8 E=2-2 IO=1-1 IR=6-6 IW=7-7 M=0-0 R=3-3 W=4-4 X=5-5 start=63-12`, then one line
per entry, for example `entry  0 istart=0x00000000800000fd  manual decode: M=1 IO=0 E=1 R=1 W=1 X=1 IR=1 IW=1 DID=0`,
`entry  2 istart=0x00000001000001a5  manual decode: M=1 IO=0 E=1 R=0 W=0 X=1 IR=0 IW=1 DID=1` and
`entry  4 istart=0x00000000600003e5  manual decode: M=1 IO=0 E=1 R=0 W=0 X=1 IR=1 IW=1 DID=3`. It prints a
`VIOLATED: ... mutually exclusive` line for all 9 entries, and `VIOLATED` lines for RAM `E`/`DID`, the flash drive
`E`/`R`/`X`/`DID` and the rx buffer `E`/`R`/`X`/`DID`. It ends with
`VIOLATED: R7/R13: the PMA words the guest reads follow the manual's documented layout`.

Since the table is parsed from the manual, a fix on either side makes the test pass. The reviewer checked this with
`MANUAL_OVERRIDE=<copy of doc/README.md with the table rewritten as start 63-12, DID 11-7, IW 6, IR 5, X 4, W 3, R 2,
IO 1, M 0>`, and the test exited 0. The reviewer did not change the test. Found, proved and reviewed on
`claude-opus-5-5`.

### Trigger and reachability

There is nothing to trigger. Every machine the emulator creates, every valid template included, has this layout in its
PMA array. Any guest code, at M-mode (and at any privilege level that can reach `0x10000`), reads the words with a plain
load. No input sequence is needed. A guest is misled only if it decodes the array with the manual's table. The guests
that ship with the emulator (Linux with OpenSBI) discover ranges from the device tree instead.

### Rating

1. Out of scope: no exclusion applies. The trigger is reading documented, guest-visible state of any machine. It
   needs no API misuse ("The effect of a deliberate state change made through the machine API"), no untrusted API
   caller, no foreign snapshot, no reload of an unguaranteed directory, and no deployment violation of A1 to A8.
2. Role: the PMA array layout belongs to the interpreter and state layout, "Interpreter, state-access layers, devices,
   uarch program, ... | Honest operator" (AUDIT.md). Section 3: the honest operator role covers "The transition
   function ... in every deployment". That clause covers this component.
3. High and Medium cases: Medium fits, "An undocumented deterministic deviation, consistent across all paths, in
   behavior that no correct guest relies on for isolation or data integrity (R7)." The encoding is deterministic. Native
   execution, the uarch and `read_word` agree (the test checks this). All of them use `pmas_pack_istart` and
   `pmas_unpack_istart`, so no hash diverges. The deviation is undocumented: the manual describes another layout. It
   is in the descriptive words of the PMA array, not in the permissions the emulator enforces, which match the
   configuration. Section 8: "A contradiction between the manual and the behavior on a security-relevant point is a
   defect in one of the two. It takes the severity it would have if the manual were right." If the manual were right,
   the code would encode a different layout. No enforcement, no hash, and no path agreement would change. That is the
   Medium case above. The Medium header also applies: "violates a rule or the manual without affecting the goal".
4. Critical: under the reading that the guest-readable PMA attributes are themselves part of R7's area "Address
   translation and memory permissions", where "any deviation lets an input subvert a correct guest, even a deviation
   that is consistent across all paths", the defect is a violation of R7 ("implements ... the devices as the manual
   documents them, departing only where the manual documents a deviation") at every reachable state, and would be
   Critical.

Two readings. The preferred one is Medium: R7's areas are the architecture a correct guest relies on for isolation
and data integrity. Here the enforced permissions are correct, and only the self-description in the PMA array differs.
No shipped or correct guest decodes that array to get its isolation. The alternative is Critical: the literal R7 text
counts any deviation in "memory permissions", and the PMA words are the guest-visible statement of those permissions.
One fact would decide it: whether a correct guest is expected to rely on the PMA array's attribute bits (rather than
the device tree) for isolation or data integrity. The manual says the array is "how the RISC-V interpreter discovers
the available ranges at runtime". That points to the interpreter, not to the guest, so it favors Medium.

### Possible solution and risks

Either fix the manual or the code. Fixing the manual: rewrite the first-word table as `start` 63-12, `DID` 11-7, `IW`
6, `IR` 5, `X` 4, `W` 3, `R` 2, `IO` 1, `M` 0. Drop the `E` bit and the "M, IO, and E are mutually exclusive" sentence,
or restate it for `M` and `IO`, and say how empty or excluded ranges are represented. This changes no hash and carries
no risk. Fixing the code instead (restoring an `E` bit and a 4-bit `DID` at 11-8) changes the state layout. That
changes every machine's root hash, the uarch program and its pristine hash, and is a new protocol version (R13, A6),
which would need the machine-identification registers bumped and the on-chain step regenerated. The manual fix is
the safer choice.

### Risk of not fixing it

No hash, proof or verification is affected, so no deployment's settlement is at risk. A guest, firmware or tool
author who follows the manual and decodes the PMA array gets wrong permissions and driver IDs for every range. For
example, they see no RAM entry with `DID` 1 and no rx buffer with `DID` 7, and may misidentify ranges. The emulator still
enforces the real permissions. Mitigation outside the code: use the device tree (as Linux does) or the code's
constants in `src/pmas-constants.hpp` instead of the manual's table.
