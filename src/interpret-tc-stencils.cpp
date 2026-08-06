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

// Copy-and-patch stencils for the tail-call JIT (tail-call.md section 5.20).
//
// This translation unit is compiled but NEVER LINKED. It exists to be mined:
// tools/gen-tc-stencils.lua reads the object file, extracts each stencil
// function's machine code and the relocations inside it, and emits
// interpret-tc-stencils.inc, which the interpreter embeds as data. At run time
// the JIT builds a trace by copying stencil bodies back to back and writing the
// recorded instruction's operands into the holes those relocations mark.
//
// Two consequences of never being linked are load-bearing. It can be compiled
// -fno-pic without the text relocations a shared library would refuse, so no
// operand reaches its use through a GOT and every stencil is relocatable by
// memcpy. And an undefined symbol is not an error here but the mechanism: a
// hole is exactly a symbol the linker would have resolved.
//
// A stencil's code may reference nothing but its holes and the state registers.
// The extractor enforces that by rejecting any relocation it cannot classify as
// a hole, which is what makes copying a stencil to an arbitrary address sound.
// Anything that would need a call (a TLB miss, a page walk, a raise) is not
// compiled at all: the stencil guards for it and side-exits to the interpreter
// before touching any state, and the interpreter re-executes that instruction
// from scratch.

#define TC_TRANSLATION_UNIT
#define TC_STENCIL_TU 1
#include "interpret.cpp"

namespace cartesi {

#include "interpret-tc-abi.hpp"

// The handler parameter macros of the argument-passing shapes name the
// accessor through the template parameter every handler is generic over.
// Stencils are concrete by construction -- there is one compiled body per
// case, not one per accessor -- so the name is bound here instead. Only
// direct execution is ever compiled, exactly as for the tail-call loop.
using STATE_ACCESS = state_access;

// The holes. Each is an undefined symbol whose *value*, not the contents at
// that address, is the operand; interpret.cpp's TC_STENCIL_TU block already
// declares the ones its operand getters use.
extern "C" {
/// \brief How far the recorded successor lies from this instruction.
/// \details A displacement rather than an address, and that is not only for
/// range. pc is a fast address, vpc plus the mapping offset K deposited at the
/// last fetch; the difference between two fast addresses taken in the same
/// instant is exactly the difference between the architectural pcs they encode,
/// because K cancels. So the guard needs neither K nor a load to find it, and
/// what it compares is a branch displacement, which fits an immediate.
extern char tc_h_next_delta[];
/// \brief Cycles pending in this block at this step, charged on every exit.
extern char tc_h_k[];
/// \brief The next stencil in the trace. Patched to a direct jump, or dropped
/// entirely when the next stencil is the next byte, which is the fall-through
/// elision that gives copy-and-patch its density.
TC_CALLCONV execute_status tc_h_cont(state_access a, uint32_t insn TC_HOT_PARAMS);
/// \brief This step's side exit: the stub that charges tc_h_k and lands in the
/// interpreter's fetch tail with the register contract already in place.
TC_CALLCONV execute_status tc_h_exit(state_access a, uint32_t insn TC_HOT_PARAMS);
}

/// \brief The recorded instruction word.
/// \details Structural fields (funct3, funct7, rm) still read the word, so a
/// case serving several encodings discriminates exactly as the interpreter
/// does. Only the operand fields are folded into the code by their own holes.
#define TC_STENCIL_INSN (static_cast<uint32_t>(TC_STENCIL_HOLE(tc_h_insn)))
#define TC_STENCIL_NEXT_DELTA (TC_STENCIL_SEXT(tc_h_next_delta))
#define TC_STENCIL_K (TC_STENCIL_HOLE(tc_h_k))

/// \brief The architectural mcycle at pending step K of the current block.
/// \details Block accounting, exactly as the AOT trace bodies of section 8b:
/// the entry guard proves the block fits before the tick end, so straight-line
/// steps carry no per-instruction countdown work and observers derive the
/// cycle they would have seen from their static position in the block.
#define TC_STENCIL_MCYCLE() (TC_MCYCLE_GET() + TC_STENCIL_K - 1)

/// \brief Leaves the trace at the current pc, charging the pending cycles.
#define TC_STENCIL_EXIT()                                                                                              \
    do {                                                                                                               \
        tc_remaining -= TC_STENCIL_K;                                                                                  \
        TC_SYNC();                                                                                                     \
        TC_MUSTTAIL return tc_h_exit(a, insn_in TC_HOT_ARGS);                                                          \
    } while (0)

/// \brief One compiled instruction.
/// \details NAME, PRELOAD and LEN come from interpret-tc-cases.inc, so the
/// classification the interpreter already carries is reused rather than
/// re-derived: class 2 is straight-line, and plain success there implies the
/// fall-through, so it needs no successor guard at all; classes 1 and 0 can
/// move pc arbitrarily and are guarded against the recorded successor.
///
/// Statuses are handled as the interpreter's own handler macro handles them: a
/// status above success poisons the fetch tag, and one at or above
/// serve_interrupts leaves the chain outright. A status of failure means the
/// instruction raised, which no stencil in the compiled set can do -- the
/// guards side-exit first -- but the branch is kept so that a mis-selected
/// case degrades into an exit rather than into wrong execution.
#define TC_STENCIL(NAME, PRELOAD, LEN, EXPR)                                                                           \
    extern "C" TC_CALLCONV execute_status tc_stencil_##NAME(const state_access a,                                      \
        [[maybe_unused]] uint32_t insn_in TC_HOT_PARAMS) {                                                             \
        TC_ENTER();                                                                                                    \
        [[maybe_unused]] const auto tc_pc_in = pc;                                                                     \
        [[maybe_unused]] const uint32_t insn = TC_STENCIL_INSN;                                                        \
        const execute_status status = (EXPR);                                                                          \
        if (status == execute_status::failure) [[unlikely]] {                                                          \
            /* A stencil cannot raise. Raising is a call, and the extractor      \
               rejects a stencil that reaches anything but its own holes, so     \
               every case in the compiled set that could raise either is not in  \
               it or bails first: the TLB consult that misses, the encoding a    \
               case rejects. Failure therefore means this instruction did not    \
               execute, so the block owes a cycle less than it would have, and   \
               the interpreter runs the instruction itself from the top. */      \
            tc_remaining -= TC_STENCIL_K - 1;                                                                          \
            TC_SYNC();                                                                                                 \
            TC_MUSTTAIL return tc_h_exit(a, insn_in TC_HOT_ARGS);                                                      \
        }                                                                                                              \
        if (status > execute_status::success) [[unlikely]] {                                                           \
            TC_FETCH_TAG_INVALIDATE();                                                                                 \
            if (status >= execute_status::success_and_serve_interrupts) [[unlikely]] {                                 \
                tc_remaining -= TC_STENCIL_K;                                                                          \
                tcc->pc = pc;                                                                                          \
                tcc->mcycle = TC_MCYCLE_GET();                                                                          \
                TC_FETCH_TAG_SYNC();                                                                                   \
                return status;                                                                                         \
            }                                                                                                          \
        }                                                                                                              \
        if constexpr ((PRELOAD) != 2) {                                                                                \
            if (pc != tc_pc_in + TC_STENCIL_NEXT_DELTA) [[unlikely]] {                                              \
                TC_STENCIL_EXIT();                                                                                     \
            }                                                                                                          \
        } else if (status != execute_status::success) [[unlikely]] {                                                   \
            /* Straight-line, but the status says the interpreter should take    \
               it from here; the instruction did retire, so the block owes it */ \
            TC_STENCIL_EXIT();                                                                                         \
        }                                                                                                              \
        TC_SYNC();                                                                                                     \
        TC_MUSTTAIL return tc_h_cont(a, insn_in TC_HOT_ARGS);                                                          \
    }

#include "interpret-tc-stencil-cases.inc"

#undef TC_STENCIL

// The control stencils. A trace is not only its instructions: it needs an entry
// guard, a place to charge the block's cycles, and a back edge. Those are
// stencils too rather than machine code the emitter writes by hand, so the
// emitter stays architecture-independent and every instruction in a trace comes
// from the same compiler as the interpreter it runs inside.

/// \brief Entry guard: enter only if the countdown covers the whole block.
/// \details This is what buys the block accounting. Having proved once, here,
/// that the tick cannot end inside the block, no step in it needs to count, and
/// the cycles are charged in one subtraction at the end. K is the block length.
extern "C" TC_CALLCONV execute_status tc_stencil_GUARD(const state_access a,
    [[maybe_unused]] uint32_t insn_in TC_HOT_PARAMS) {
    TC_ENTER();
    if (static_cast<int64_t>(tc_remaining) < static_cast<int64_t>(TC_STENCIL_K)) [[unlikely]] {
        TC_SYNC();
        TC_MUSTTAIL return tc_h_exit(a, insn_in TC_HOT_ARGS);
    }
    TC_SYNC();
    TC_MUSTTAIL return tc_h_cont(a, insn_in TC_HOT_ARGS);
}

/// \brief Charges a completed block's cycles and carries on.
extern "C" TC_CALLCONV execute_status tc_stencil_CHARGE(const state_access a,
    [[maybe_unused]] uint32_t insn_in TC_HOT_PARAMS) {
    TC_ENTER();
    tc_remaining -= TC_STENCIL_K;
    TC_SYNC();
    TC_MUSTTAIL return tc_h_cont(a, insn_in TC_HOT_ARGS);
}

/// \brief Loop back edge: charge the iteration, then prove the next one fits.
/// \details It does not check that execution arrived back at the loop head,
/// because the step before it already did: the last instruction of a cyclic
/// recording is guarded against its recorded successor, and that successor is
/// the loop head. The emitter refuses to close a cycle on a step that carries
/// no such guard, so the property this omits is one the layout guarantees.
extern "C" TC_CALLCONV execute_status tc_stencil_LOOP(const state_access a,
    [[maybe_unused]] uint32_t insn_in TC_HOT_PARAMS) {
    TC_ENTER();
    tc_remaining -= TC_STENCIL_K;
    if (static_cast<int64_t>(tc_remaining) >= static_cast<int64_t>(TC_STENCIL_K)) [[likely]] {
        TC_SYNC();
        TC_MUSTTAIL return tc_h_cont(a, insn_in TC_HOT_ARGS);
    }
    TC_SYNC();
    TC_MUSTTAIL return tc_h_exit(a, insn_in TC_HOT_ARGS);
}

/// \brief What the stencils were compiled against.
/// \details The extractor copies these into the generated table and the
/// interpreter static_asserts them against its own build, because a stencil is
/// only relocatable into a chain compiled against the identical contract: the
/// context layout it addresses through tcc and the shape flags that decide
/// which registers hold what. Getting this wrong produces code that runs and
/// is silently wrong, which is the one failure mode this experiment has
/// already been bitten by (section 8b, the head-keying repair).
extern "C" const uint64_t tc_stencil_abi[] = {
    sizeof(tc_context<state_access>),
    offsetof(tc_context<state_access>, pc),
    offsetof(tc_context<state_access>, mcycle),
    offsetof(tc_context<state_access>, mcycle_tick_end),
    offsetof(tc_context<state_access>, fetch_vaddr_page),
    offsetof(tc_context<state_access>, fetch_pma_index),
    TC_GLOBAL_REGS,
    TC_PAGE_SEGMENT,
    TC_USE_PRESERVE_NONE,
    TC_JIT_SHELL,
};

} // namespace cartesi
