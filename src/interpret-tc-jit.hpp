// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

/// \file
/// \brief The copy-and-patch backend: turns a recorded trace into machine code.
/// \details Included by interpret-tc.cpp after the generated stencil table,
/// from inside namespace cartesi. A trace is built by copying stencil bodies
/// back to back into the code cache and writing the recorded instruction's
/// operands into the holes the extractor marked. There is no register
/// allocation and no instruction selection: the stencils were compiled against
/// the interpreter's own handler contract, so a compiled trace is entered and
/// left by a plain jump with the state already in the registers it belongs in.
///
/// What the emitter has to get right is therefore not code generation but
/// accounting and control flow: which cycles a block owes, where a guard goes,
/// and where each exit lands.

namespace {

/// \brief Executable memory for compiled traces.
/// \details One cache per host thread, matching the recorder it serves; the
/// production shape is per machine, allocated at creation (tail-call.md section
/// 8b, step 3). Bump-allocated and flushed whole, so nothing is ever freed
/// individually and no compiled trace can outlive the head table that names it.
///
/// The cache is mapped near the library's own text on purpose. A stencil leaves
/// its continuations and side exits as 32-bit displacements, which is the
/// encoding that makes them free; those have to reach the interpreter, so the
/// cache has to land within reach of it. Every displacement is range-checked
/// when written and the trace is discarded if one does not fit, which turns the
/// one thing this assumption could cost into a missed optimization.
struct tc_jit_cache {
    static constexpr size_t capacity = 4U << 20U;
    /// \brief How far a 32-bit displacement reaches, less a margin.
    static constexpr uintptr_t reach = (1U << 31U) - (64U << 20U);

    uint8_t *base = nullptr;
    size_t used = 0;
    bool executable = false;
    bool failed = false;

    // Statistics, reported under TC_JIT_STATS
    uint64_t compiled = 0;   ///< Traces turned into machine code
    uint64_t rejected = 0;   ///< Recordings the compiled set could not cover
    uint64_t truncated = 0;  ///< Traces cut short at an uncompilable instruction
    uint64_t out_of_reach = 0;
    uint64_t flushes = 0;
    uint64_t bytes = 0;
    uint64_t loops = 0;     ///< interpret() calls, each of which rebuilds the head table
    uint64_t cyclic = 0;    ///< Compiled traces that close a loop
    uint64_t steps = 0;     ///< Instructions compiled, summed over traces
#if TC_JIT_COVERAGE
    uint64_t per_head[TC_HEAD_SLOTS] = {};
    uint64_t per_head_pc[TC_HEAD_SLOTS] = {};
#endif
    uint64_t insns = 0;     ///< Guest instructions retired inside compiled code
    uint64_t entered = 0;   ///< Dispatches into compiled code
    uint64_t stale = 0;     ///< Head hits refused because the context changed
    uint64_t stale_miss = 0;///< ...of those, because the code TLB did not hold the page
    uint64_t stale_remap = 0;///< ...of those, because it held a different host page
    uint64_t per_stencil[512] = {}; ///< compiled steps per stencil, for TC_JIT_STATS
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
THREAD_LOCAL tc_jit_cache tc_jit_storage;

/// \brief Reserves the code cache next to the interpreter it will jump into.
static bool tc_jit_open(tc_jit_cache *c) {
    if (c->base != nullptr) {
        return true;
    }
    if (c->failed) {
        return false;
    }
    // Anchor on code in this library, then walk away from it in steps until the
    // kernel gives us something; anything it returns is checked for reach below
    // rather than trusted, because a hint is only ever advisory.
    const auto anchor = reinterpret_cast<uintptr_t>(&tc_jit_open);
    const uintptr_t page = 1U << 20U;
    for (uintptr_t delta = page; delta < tc_jit_cache::reach; delta *= 2) {
        for (const int sign : {-1, 1}) {
            auto hint = anchor + static_cast<uintptr_t>(sign) * delta;
            hint &= ~(page - 1);
            void *p = mmap(reinterpret_cast<void *>(hint), tc_jit_cache::capacity, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) {
                continue;
            }
            const auto got = reinterpret_cast<uintptr_t>(p);
            const uintptr_t far = got > anchor ? got - anchor : anchor - got;
            if (far + tc_jit_cache::capacity < tc_jit_cache::reach) {
                c->base = static_cast<uint8_t *>(p);
                c->used = 0;
                c->executable = false;
                return true;
            }
            munmap(p, tc_jit_cache::capacity);
        }
    }
    c->failed = true;
    return false;
}

/// \brief Makes the cache writable to emit into, or executable to run from.
/// \details Write and execute are never both granted. Traces are installed a
/// few hundred times in a run, so paying two calls each time costs nothing
/// measurable and keeps the pages from being writable while the guest runs.
static void tc_jit_protect(tc_jit_cache *c, bool executable) {
    if (c->base == nullptr || c->executable == executable) {
        return;
    }
    if (mprotect(c->base, tc_jit_cache::capacity, executable ? (PROT_READ | PROT_EXEC) : (PROT_READ | PROT_WRITE)) !=
        0) {
        c->failed = true;
        return;
    }
    c->executable = executable;
}

/// \brief Writes one hole into a copied stencil body.
/// \details The relocation kinds are the ones the stencils actually produce,
/// checked by the extractor, so an unexpected one cannot reach here. A
/// displacement that does not fit fails the trace instead of being truncated.
static bool tc_jit_patch(uint8_t *site, tc_patch_kind kind, uint64_t value, int64_t addend) {
    switch (kind) {
        case TC_PATCH_ABS64: {
            const uint64_t v = value + static_cast<uint64_t>(addend);
            memcpy(site, &v, sizeof(v));
            return true;
        }
        case TC_PATCH_ABS32:
        case TC_PATCH_ABS32S: {
            const auto v = static_cast<int64_t>(value) + addend;
            // Only the low 32 bits are written, and whether the code around
            // the site treats them as signed is the code's business, not the
            // relocation's: a sign-extending instruction follows some of these
            // sites and a zero-extending one follows others. So what is checked
            // here is only that 32 bits can represent the value at all, as
            // either sign. Which extension a given site actually performs is
            // settled in the stencil source, by keeping signed operands
            // narrowed to int32_t so the sign extension is written down rather
            // than left to the compiler's choice of encoding -- a Clang build
            // that chose the zero-extending one turned every backward branch
            // offset positive and trapped the guest.
            if (v < INT32_MIN || v > UINT32_MAX) {
                return false;
            }
            const auto v32 = static_cast<uint32_t>(static_cast<int64_t>(v));
            memcpy(site, &v32, sizeof(v32));
            return true;
        }
        case TC_PATCH_REL32: {
            // S + A - P, the displacement from the field itself
            const int64_t v =
                static_cast<int64_t>(value) + addend - static_cast<int64_t>(reinterpret_cast<uintptr_t>(site));
            if (v < INT32_MIN || v > INT32_MAX) {
                return false;
            }
            const auto v32 = static_cast<int32_t>(v);
            memcpy(site, &v32, sizeof(v32));
            return true;
        }
        default:
            return false;
    }
}

/// \brief What a step's holes are filled with.
struct tc_jit_operands {
    uint32_t insn;      ///< The recorded instruction word
    int64_t next_delta; ///< How far the recorded successor lies from this step
    uint64_t k;       ///< Cycles this block owes once this step has run
    const void *cont; ///< Where this stencil continues
    const void *exit; ///< Where it leaves for the interpreter
};

/// \brief The value of one hole, computed by the getter the hole stands for.
/// \details This is the whole reason there is a hole per getter rather than a
/// hole per operand kind: the JIT decodes a recorded instruction with the same
/// functions the interpreter decodes it with, so the two cannot disagree about
/// what an immediate means. Register holes carry a byte offset, the form their
/// stencil folded into an addressing displacement.
static uint64_t tc_jit_hole_value(tc_hole_kind hole, const tc_jit_operands &op) {
    const uint32_t insn = op.insn;
    constexpr uint64_t xslot = sizeof(uint64_t);
    switch (hole) {
        case TC_HOLE_INSN:
            return insn;
        case TC_HOLE_RD:
            return insn_get_rd(insn) * xslot;
        case TC_HOLE_RS1:
            return insn_get_rs1(insn) * xslot;
        case TC_HOLE_RS2:
            return insn_get_rs2(insn) * xslot;
        case TC_HOLE_C_RD_RS2:
            return insn_get_CIW_CL_rd_CS_CA_rs2(insn) * xslot;
        case TC_HOLE_C_RS1:
            return insn_get_CL_CS_CA_CB_rs1(insn) * xslot;
        case TC_HOLE_C_RS2:
            return insn_get_CR_CSS_rs2(insn) * xslot;
        case TC_HOLE_IMM_I:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_I_get_imm(insn)));
        case TC_HOLE_IMM_IU:
            return insn_I_get_uimm(insn);
        case TC_HOLE_IMM_U:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_U_get_imm(insn)));
        case TC_HOLE_IMM_B:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_B_get_imm(insn)));
        case TC_HOLE_IMM_J:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_J_get_imm(insn)));
        case TC_HOLE_IMM_S:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_S_get_imm(insn)));
        case TC_HOLE_IMM_CJ:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_J_imm(insn)));
        case TC_HOLE_IMM_CBEQZ:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_BEQZ_BNEZ_imm(insn)));
        case TC_HOLE_IMM_CLCS:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_CL_CS_imm(insn)));
        case TC_HOLE_IMM_CICB:
            return insn_get_CI_CB_imm(insn);
        case TC_HOLE_IMM_CICBSE:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_CI_CB_imm_se(insn)));
        case TC_HOLE_IMM_CLW:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_LW_C_SW_imm(insn)));
        case TC_HOLE_IMM_CLSB:
            return insn_get_C_LS_B_uimm(insn);
        case TC_HOLE_IMM_CLSH:
            return insn_get_C_LS_H_uimm(insn);
        case TC_HOLE_IMM_CIW:
            return insn_get_CIW_imm(insn);
        case TC_HOLE_IMM_CADDI16SP:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_ADDI16SP_imm(insn)));
        case TC_HOLE_IMM_CLUI:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_LUI_imm(insn)));
        case TC_HOLE_IMM_CLDSP:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_FLDSP_LDSP_imm(insn)));
        case TC_HOLE_IMM_CLWSP:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_LWSP_imm(insn)));
        case TC_HOLE_IMM_CSDSP:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_FSDSP_SDSP_imm(insn)));
        case TC_HOLE_IMM_CSWSP:
            return static_cast<uint64_t>(static_cast<int64_t>(insn_get_C_SWSP_imm(insn)));
        case TC_HOLE_NEXT_DELTA:
            return static_cast<uint64_t>(op.next_delta);
        case TC_HOLE_K:
            return op.k;
        case TC_HOLE_CONT:
            return reinterpret_cast<uintptr_t>(op.cont);
        case TC_HOLE_EXIT:
            return reinterpret_cast<uintptr_t>(op.exit);
        default:
            return 0;
    }
}

/// \brief Copies one stencil into the cache and fills its holes.
/// \details The continuation is left unpatched when it is the stencil that
/// follows, and the trailing jump is dropped with it: that is the fall-through
/// elision copy-and-patch is named for, and on a straight run of instructions
/// it removes one jump per guest instruction.
/// \returns Bytes emitted, or 0 if the trace cannot be built.
static size_t tc_jit_emit(tc_jit_cache *c, uint16_t stencil, tc_jit_operands op, bool next_follows) {
    const tc_stencil_desc &d = tc_stencil_table[stencil];
    size_t size = d.size;
    // The jump can only be dropped when it is physically last, which is where
    // the compiler puts it for a stencil whose hot path falls out of the bottom
    // -- the straight-line cases, and they are the bulk. A guarded case ends
    // with its exit path instead and keeps the jump, which then simply targets
    // the next stencil rather than being elided.
    if (next_follows) {
        for (uint16_t i = 0; i < d.nholes; ++i) {
            const tc_stencil_hole &h = tc_stencil_holes[d.hole_off + i];
            // Ending with the displacement is not enough to know the jump is
            // unconditional: a conditional one ends the same way but is two
            // opcode bytes, and cutting at one would leave half an instruction
            // behind. Require the encoding, and simply keep the jump otherwise.
            if (h.hole == TC_HOLE_CONT && h.off + sizeof(uint32_t) == d.size && h.off >= 1 &&
                tc_stencil_code[d.code_off + h.off - 1] == 0xE9) {
                size = h.off - 1; // and the jump's opcode byte with it
                break;
            }
        }
    }
    if (c->used + size > tc_jit_cache::capacity) {
        return 0;
    }
    uint8_t *at = c->base + c->used;
    if (next_follows) {
        // Whatever is emitted next begins right after this body. When the jump
        // was elided this is unused, because the hole went with it.
        op.cont = at + size;
    }
    memcpy(at, tc_stencil_code + d.code_off, size);
    for (uint16_t i = 0; i < d.nholes; ++i) {
        const tc_stencil_hole &h = tc_stencil_holes[d.hole_off + i];
        if (h.off + sizeof(uint32_t) > size) {
            continue; // inside the elided jump
        }
        if (!tc_jit_patch(at + h.off, h.patch, tc_jit_hole_value(h.hole, op), h.addend)) {
            ++c->out_of_reach;
            if (std::getenv("TC_JIT_DEBUG") != nullptr) {
                std::fprintf(stderr, "tc-jit: hole %d kind %d value %llx addend %lld did not fit\n",
                    static_cast<int>(h.hole), static_cast<int>(h.patch),
                    static_cast<unsigned long long>(tc_jit_hole_value(h.hole, op)),
                    static_cast<long long>(h.addend));
            }
            return 0;
        }
    }
    c->used += size;
    return size;
}

/// \brief Whether a stencil verifies where execution went after it.
/// \details Straight-line cases carry no successor guard, because plain success
/// already implies the fall-through. A cycle may only be closed on a case that
/// does carry one, since the back edge relies on that guard having proved that
/// execution arrived back at the loop head.
static bool tc_jit_is_guarded(uint16_t stencil) {
    const tc_stencil_desc &d = tc_stencil_table[stencil];
    for (uint16_t i = 0; i < d.nholes; ++i) {
        if (tc_stencil_holes[d.hole_off + i].hole == TC_HOLE_NEXT_DELTA) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace
