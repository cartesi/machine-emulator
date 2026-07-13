# Decoded Instruction Cache: payload usage per instruction

Each decoded cache entry is 16 bytes: `{handler ptr, int32 payload, u32 insn}`.
The payload carries pre-decoded data whose meaning is defined per specialized (`D_*`)
handler. Two layouts are used:

- **full-imm**: the whole 32-bit payload is a pre-decoded (sign-extended) immediate.
- **packed** (`make_decoded_payload(imm, b, a)`): `imm` in bits [31:16] (signed, unpacks
  with one arithmetic shift), field `b` in [15:8] and field `a` in [7:0], both pre-masked
  so each unpacks with a single shift/mask.

## Instructions using the payload

### Full-imm layout (pre-decoded jump/branch offset)
| instruction | payload | what execution saves |
|---|---|---|
| jal (rd0/rdN) | J-imm (±1MB, needs full 32 bits) | 4-op scattered-bit extraction off the taken-jump serial chain |
| beq, bne, blt, bge, bltu, bgeu | B-imm | 4-op extraction off the taken-branch chain (the +110% taken-branch win) |
| c.j | CJ-imm | 4-op extraction off the jump chain |
| c.beqz, c.bnez | CB-imm | 3-op extraction off the taken-branch chain |
| c.lui | 17-bit imm (does not fit packed layout) | 3-op extraction; rd comes from insn |

### Packed layout {imm16, b, a}
| instruction(s) | packing | what execution saves |
|---|---|---|
| lb, lh, lw, ld, lbu, lhu, lwu (rdN) | {I-imm, rs1, rd} | pre-masked rs1 lands one op earlier on the load-address chain; imm+rd extraction gone |
| sb, sh, sw, sd | {S-imm, rs1, rs2} | ditto for the store-address chain; S-imm is a 2-op split-field extraction |
| jalr (rd0/rdN) | {I-imm, rs1, rd} | field extraction around the indirect-jump chain |
| c.addi | {CI-imm, rd, rd} | 3-op scattered-bit imm extraction |
| c.addiw, c.li, c.andi | {CI-imm, rs1', rs1'} / {CI-imm, rd, rd} | ditto |
| c.addi16sp | {imm, 2, 2} → shares D_C_ADDI | 5-op imm extraction; alias resolved at decode |
| c.addi4spn | {imm, 2, rd'} → shares D_C_ADDI | 4-op zext-imm extraction; alias resolved at decode |
| c.slli, c.srli, c.srai | {shamt, rd/rs1', rd/rs1'} | shamt extraction |
| c.mv, c.add | {0, rs2, rd} | 2×2-op field extraction |
| c.sub, c.xor, c.or, c.and, c.subw, c.addw, c.mul | {0, rs2', rs1'} | ditto (rd = rs1 for CA format) |
| c.lw, c.ld, c.fld | {uimm, rs1', rd'} | scattered uimm + 2 field extractions off the address chain |
| c.lwsp, c.ldsp, c.fldsp | {uimm, 2, rd} → share D_C_LW/LD/FLD | SP-alias resolved at decode |
| c.sw, c.sd, c.fsd | {uimm, rs1', rs2'} | ditto for stores |
| c.swsp, c.sdsp, c.fsdsp | {uimm, 2, rs2} → share D_C_SW/SD/FSD | SP-alias resolved at decode |
| c.jr, c.jalr | {0, 0, rs1} | rs1 extraction off the indirect-jump chain |

## Instructions that jump directly to their exact operation, fields from insn

The decode cache resolves the funct7 sub-opcode once (killing the per-execution probe and
illegal-encoding check), but register fields are deliberately read from `insn`:

add, sub, sll, slt, sltu, xor, srl, sra, or, and, mul, mulh, mulhsu, mulhu, div, divu,
rem, remu, addw, subw, mulw, srlw, sraw, divuw, srli, srai, srliw, sraiw.

**Why they do NOT use the payload for rd/rs1/rs2 — measured, not assumed** (experiment
"Q5", see OPTIM_REPORT.md): at handler time `insn` is already in a host register (loaded
at dispatch), so a field costs 2 ALU ops. The payload would be a fresh 4-byte memory load
(~5 cycles) feeding the `x[rs1]`/`x[rs2]` read addresses — for dependent guest ALU chains
this puts a load on the result serial chain. Forcing all ALU fields through the payload
measured **−30..−45% on every stress benchmark** (regs 1520→775, cpu 629→466, memcpy
1249→761) with identical instruction counts and identical cache/branch-miss counters:
pure added chain latency. The rule this experiment established:

> The payload only pays for a field when it is (a) off the result chain (branch/jump
> immediates consumed after a predicted condition, rd write ports), or (b) expensive to
> extract (scattered compressed immediates, S-imm splits), or (c) feeding a chain long
> enough to hide the payload load (load/store address chains that continue into the TLB
> probe). Chain-critical fields of short ALU handlers must come from insn.

Loads/stores tolerate the payload for rs1 because their handlers are long (TLB probe +
memory access) and the pre-masked rs1 nets one op earlier on that longer chain — this was
measured as memcpy +29%, not assumed.

## Not specialized (original handlers, table-direct)

- Instructions whose jump-table entry already identifies the exact operation and whose
  handlers are trivial: lui, auipc, addi/slti/sltiu/xori/ori/andi/slli/addiw/slliw
  (I-type ALU: 1-2 op imm extraction, rs1 chain-critical → insn is optimal per the rule
  above), sllw, divw, remw, remuw, fence, fence.i, c.nop, c.hint, Zcb extensions.
- rd = x0 variants of everything (hints/nops, ~0% dynamic frequency).
- AMO family, FP (FD/FMA groups), csr*, privileged: decode-time resolution was
  implemented and correct ("Q4") but measured net-negative — their stubs perturb code
  layout for operations too rare to pay for it. Documented in OPTIM_REPORT.md; revisit
  only with hot/cold text placement control.

## Verification (this exact build)

- `make test-machine`: 267/267 passed
- `make test-uarch-compare` (fast-vs-uarch determinism): 102/102 passed
- `hash-check.lua` (Linux boot + 400Mi cycles stress): root hash bit-identical to the
  pristine interpreter
- clang-format clean
- Full pinned bench-stress: nop 1818, regs 1522, cpu 630, fp 1004, crypt 892,
  memcpy 1249, branch 799, heapsort 906, tsearch 584, matrix-3d 234, tree 574,
  malloc 316, randlist 617 (12 of 13 above the pre-decode-cache baseline)
