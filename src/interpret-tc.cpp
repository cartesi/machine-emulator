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

// Tail-call threaded interpreter (see tail-call.md). It lives in its own
// translation unit because the pinned register discipline is TU-wide: GCC's
// register-asm declarations reserve the registers for the whole translation
// unit, and Clang additionally requires -ffixed-x23 through -ffixed-x27 on
// the command line of this file. Keeping it out of interpret.cpp spares the
// stock loop instantiations (record, replay, collect) that reservation.
// Only direct execution (state_access) dispatches through this loop.

#define TC_TRANSLATION_UNIT
#include "interpret.cpp"

namespace cartesi {

/// \brief Mutable interpreter loop state committed by the tail-call handler chain when it stops.
/// \details Hot values (pc, insn, the cycle countdown) travel in the fixed
/// handler state instead; pc and mcycle are stored here only when a handler
/// returns to the outer loop. mcycle itself is not kept live: the chain
/// carries a countdown of cycles until the tick end, and the architectural
/// mcycle is materialized as mcycle_tick_end - countdown at the few points
/// that observe it (the privileged handler, chain exits).
template <typename STATE_ACCESS>
struct tc_context {
    uint64_t pc;
    uint64_t mcycle;
    uint64_t mcycle_end;
    uint64_t mcycle_tick_end;
    uint64_t fetch_vaddr_page;
    i_state_access_fast_addr_t<STATE_ACCESS> fetch_vf_offset;
    uint64_t fetch_pma_index;
};

// Both compilers default to the unified shape: the interpreter's hot state
// pinned in the call-saved registers x23-x27, with the next-instruction
// pre-load, and (under Clang) the preserve_none convention and guaranteed
// tail calls layered on. Every choice can be overridden from the build for
// experiments (-DTC_GLOBAL_REGS=0/1, -DTC_PRELOAD_ENABLED=0/1,
// -DTC_USE_PRESERVE_NONE=0/1, -DTC_MUSTTAIL=).
//
// The register-asm declarations reserve the pinned registers in this
// translation unit (Clang additionally requires -ffixed-x23 through
// -ffixed-x27 on this file's command line, which the tailcall=yes build
// passes), and being call-saved they survive calls into code compiled
// elsewhere. pc crosses the execute_* reference boundary, so handlers bind
// it to a local and sync it at every exit.
#ifndef TC_GLOBAL_REGS
#ifdef __aarch64__
#define TC_GLOBAL_REGS 1
#else
#define TC_GLOBAL_REGS 0
#endif
#endif

#if TC_GLOBAL_REGS && !defined(__aarch64__)
#error "TC_GLOBAL_REGS requires AArch64"
#endif

// preserve_none composes with pinned registers: the pinned state is not
// passed at all, but the convention still frees handlers from callee-saved
// prologue obligations. Its argument assignment uses x20-x28 in order and
// ignores -ffixed reservations, which is why the pinned set starts at x23,
// leaving x20-x22 for the (accessor, insn) arguments.
#ifndef TC_USE_PRESERVE_NONE
#if defined(__clang__) && __has_attribute(preserve_none)
#define TC_USE_PRESERVE_NONE 1
#else
#define TC_USE_PRESERVE_NONE 0
#endif
#endif

#if TC_USE_PRESERVE_NONE
#define TC_CALLCONV __attribute__((preserve_none))
#else
#define TC_CALLCONV
#endif

// The next-instruction pre-load pays for itself only when the register
// budget keeps the extra predicted state (word, dispatch target) in
// registers across the handler body; with neither pinned globals nor
// preserve_none it turns into hot-path stack traffic on already
// ABI-strained handlers.
#ifndef TC_PRELOAD_ENABLED
#if TC_GLOBAL_REGS || (defined(__clang__) && __has_attribute(preserve_none))
#define TC_PRELOAD_ENABLED 1
#else
#define TC_PRELOAD_ENABLED 0
#endif
#endif

#ifndef TC_MUSTTAIL
#if defined(__clang__)
#define TC_MUSTTAIL [[clang::musttail]]
#else
#define TC_MUSTTAIL
#endif
#endif

#if TC_GLOBAL_REGS
// The interpreter's hot state lives in reserved call-saved registers, named
// so the shared handler body text resolves to them directly. pc is one
// exception (execute_* takes it by reference and register globals have no
// address), so handlers bind it to a local via TC_ENTER and sync it back
// via TC_SYNC before dispatching. The fetch offset is the other (Clang
// restricts named registers to integer and pointer types, so the register
// holds the raw value): TC_ENTER binds a read-only local of the strong
// type, and the few writers cast.
// The pinned set starts at x23 because Clang's preserve_none argument order
// assigns the handler arguments to x20-x22 even when those registers are
// reserved with -ffixed; pinning x22 would let every dispatch clobber pc
// with the instruction word.
// mcycle is not kept live: tc_remaining counts down the cycles until the
// tick end, one fused decrement-and-branch per instruction, and the
// architectural mcycle is materialized as tcc->mcycle_tick_end minus the
// countdown at the few points that observe it. The countdown is unsigned
// but compared as signed: the privileged handler (WFI polling in
// interactive mode) can push mcycle past the tick end, driving it negative.
register uint64_t tc_reg_pc asm("x23");
register uint64_t tc_remaining asm("x24");
register uint64_t fetch_vaddr_page asm("x25");
register uint64_t tc_reg_vf_offset asm("x26");
register tc_context<state_access> *tcc asm("x27");
#define TC_HOT_PARAMS
#define TC_HOT_ARGS
#define TC_ENTER()                                                                                                     \
    uint64_t pc = tc_reg_pc;                                                                                           \
    const auto fetch_vf_offset = static_cast<i_state_access_fast_addr_t<state_access>>(tc_reg_vf_offset)
#define TC_SYNC() (tc_reg_pc = pc)
#else
// The fetch cache's two hot fields travel as handler arguments: the pre-load
// consumes them at the head of its dependency chain, where keeping them in
// registers is worth several percent. The tc_context copies are kept coherent
// at every outlined-helper call and chain exit, and remain the storage the
// outer loop and the helpers use.
#define TC_HOT_PARAMS                                                                                                  \
    , uint64_t pc, uint64_t tc_remaining, tc_context<STATE_ACCESS> *tcc, uint64_t fetch_vaddr_page,                    \
        i_state_access_fast_addr_t<STATE_ACCESS> fetch_vf_offset
#define TC_HOT_ARGS , pc, tc_remaining, tcc, fetch_vaddr_page, fetch_vf_offset
#define TC_ENTER() ((void) 0)
#define TC_SYNC() ((void) 0)
#endif

// The architectural cycle counter, derived from the countdown on demand
#define TC_MCYCLE_GET() (tcc->mcycle_tick_end - tc_remaining)
#define TC_MCYCLE_SET(v) (tc_remaining = tcc->mcycle_tick_end - (v))
// One instruction retires: count it and test for the tick boundary
#define TC_TICK_ENDED() (static_cast<int64_t>(--tc_remaining) <= 0)

template <typename STATE_ACCESS>
using tc_handler_fn = TC_CALLCONV execute_status(STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS);

template <typename STATE_ACCESS>
using tc_handler_ptr = tc_handler_fn<STATE_ACCESS> *;

// Forward-declare one handler per jump-table label so the table can reference them all
#define TC_CASE(NAME, PRELOAD, LEN, EXPR)                                                                              \
    template <typename STATE_ACCESS>                                                                                   \
    TC_CALLCONV static execute_status tc_handler_##NAME(STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS);
#include "interpret-tc-cases.inc"
#undef TC_CASE

template <typename STATE_ACCESS>
static const tc_handler_ptr<STATE_ACCESS> tc_jumptable[65536] = {
#define TC_LABEL(x) tc_handler_##x<STATE_ACCESS>
#include "interpret-tc-table.inc"
#undef TC_LABEL
};

/// \brief Result of an outlined tail-call fetch helper; fits in a register pair.
/// \details The outlined helpers deliberately take pc by value and return it
/// here instead of through a reference: a reference parameter to a genuine
/// call would make the handler's pc local address-taken, forcing a stack
/// store/reload of pc onto the hot dispatch path of every handler.
struct tc_walk_result {
    fetch_status status;
    uint64_t pc;
};
static_assert(sizeof(tc_walk_result) <= 16);

/// \brief Outlined page-table walk for the tail-call fetch path (true code TLB miss).
/// \details On success, the translated vf_offset/pma_index are stored into the
/// tc_context; on exception, fetch_translate_pc_slow updates
/// tcc->fetch_vaddr_page (the fetch-cache invalidation) through the reference
/// it receives.
template <typename STATE_ACCESS>
[[gnu::noinline]] static tc_walk_result tc_fetch_translate_pc_walk(const STATE_ACCESS a, uint64_t pc, uint64_t vaddr,
    tc_context<STATE_ACCESS> *tcc) {
    i_state_access_fast_addr_t<STATE_ACCESS> vf_offset{};
    uint64_t pma_index{};
    const fetch_status status = fetch_translate_pc_slow(a, pc, vaddr, vf_offset, pma_index, tcc->fetch_vaddr_page);
    if (status == fetch_status::success) [[likely]] {
        tcc->fetch_vf_offset = vf_offset;
        tcc->fetch_pma_index = pma_index;
    }
    return {status, pc};
}

/// \brief TLB consult for the tail-call fetch path; mirrors fetch_translate_pc
/// but keeps only the TLB-hit path inline, outlining the walk.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status tc_fetch_translate_pc(const STATE_ACCESS a, uint64_t &pc, uint64_t vaddr,
    i_state_access_fast_addr_t<STATE_ACCESS> &vf_offset, uint64_t &pma_index, tc_context<STATE_ACCESS> *tcc) {
    const uint64_t slot_index = tlb_slot_index(vaddr);
    uint64_t slot_vaddr_page = a.template read_tlb_vaddr_page<TLB_CODE>(slot_index);
    bool walk = false;
    if (!tlb_is_hit<uint16_t>(slot_vaddr_page, vaddr)) [[unlikely]] {
        slot_vaddr_page = a.template init_hot_tlb_slot<TLB_CODE>(slot_index);
        walk = !tlb_is_hit<uint16_t>(slot_vaddr_page, vaddr);
    }
    if (!walk && !a.template verify_cold_tlb_slot<TLB_CODE>(slot_index)) [[unlikely]] {
        walk = true;
    }
    if (walk) [[unlikely]] {
        DUMP_STATS_INCR(a, "tlb.cmiss");
        const tc_walk_result result = tc_fetch_translate_pc_walk(a, pc, vaddr, tcc);
        pc = result.pc;
        if (result.status == fetch_status::success) [[likely]] {
            vf_offset = tcc->fetch_vf_offset;
            pma_index = tcc->fetch_pma_index;
        }
        return result.status;
    }
    vf_offset = a.template read_tlb_vf_offset<TLB_CODE>(slot_index);
    pma_index = a.template read_tlb_pma_index<TLB_CODE>(slot_index);
    DUMP_STATS_INCR(a, "tlb.chit");
    return fetch_status::success;
}

/// \brief Result of the outlined page-boundary-crossing fetch; fits in a register pair.
struct tc_crossing_result {
    fetch_status status;
    uint32_t insn;
    uint64_t pc;
};
static_assert(sizeof(tc_crossing_result) <= 16);

/// \brief Outlined fetch for a pc crossing a page boundary (rare: last 2 bytes of a page).
template <typename STATE_ACCESS>
[[gnu::noinline]] static tc_crossing_result tc_fetch_insn_crossing(const STATE_ACCESS a, uint64_t pc,
    i_state_access_fast_addr_t<STATE_ACCESS> faddr, tc_context<STATE_ACCESS> *tcc) {
    uint16_t insn16 = 0;
    a.template read_memory_word<uint16_t>(faddr, tcc->fetch_pma_index, &insn16);
    uint32_t insn = insn16;
    if (insn_is_uncompressed(insn)) [[unlikely]] {
        const uint64_t pc2 = pc + 2;
        i_state_access_fast_addr_t<STATE_ACCESS> pc2_vf_offset{};
        uint64_t pc2_pma_index{};
        if (fetch_translate_pc(a, pc, pc2, pc2_vf_offset, pc2_pma_index, tcc->fetch_vaddr_page) ==
            fetch_status::exception) [[unlikely]] {
            return {fetch_status::exception, 0, pc};
        }
        tcc->fetch_vaddr_page = tlb_addr_page(pc2);
        tcc->fetch_vf_offset = pc2_vf_offset;
        tcc->fetch_pma_index = pc2_pma_index;
        faddr = pc2 + pc2_vf_offset;
        a.template read_memory_word<uint16_t>(faddr, tcc->fetch_pma_index, &insn16);
        insn |= static_cast<uint32_t>(insn16) << 16;
    }
    return {fetch_status::success, insn, pc};
}

/// \brief Fetch for the tail-call dispatch tail; mirrors fetch_insn with the
/// fetch cache in the tc_context. The code-page-cache hit and the TLB consult
/// stay inline in each handler; only the page-table walk and the boundary
/// crossing are out of line.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status tc_fetch_insn(const STATE_ACCESS a, uint64_t &pc, uint32_t &insn,
    uint64_t &fetch_vaddr_page, i_state_access_fast_addr_t<STATE_ACCESS> &fetch_vf_offset,
    tc_context<STATE_ACCESS> *tcc) {
    if (fetch_cache_is_hit(pc, fetch_vaddr_page)) [[likely]] {
        a.template read_memory_word<uint32_t, uint16_t>(pc + fetch_vf_offset, tcc->fetch_pma_index, &insn);
        return fetch_status::success;
    }
    i_state_access_fast_addr_t<STATE_ACCESS> faddr{0};
    const uint64_t pc_vaddr_page = tlb_addr_page(pc);
    if (pc_vaddr_page == fetch_vaddr_page) [[unlikely]] {
        faddr = pc + fetch_vf_offset;
    } else {
        i_state_access_fast_addr_t<STATE_ACCESS> pc_vf_offset{};
        uint64_t pc_pma_index{};
        if (tc_fetch_translate_pc(a, pc, pc, pc_vf_offset, pc_pma_index, tcc) == fetch_status::exception) [[unlikely]] {
            // The slow path invalidated the stored fetch cache with the exception handler pc
            fetch_vaddr_page = tcc->fetch_vaddr_page;
            return fetch_status::exception;
        }
        fetch_vaddr_page = pc_vaddr_page;
        fetch_vf_offset = pc_vf_offset;
        tcc->fetch_vaddr_page = pc_vaddr_page;
        tcc->fetch_vf_offset = pc_vf_offset;
        tcc->fetch_pma_index = pc_pma_index;
        faddr = pc + pc_vf_offset;
    }
    if (((~pc & PAGE_OFFSET_MASK) >> 1) == 0) [[unlikely]] {
        const tc_crossing_result result = tc_fetch_insn_crossing(a, pc, faddr, tcc);
        pc = result.pc;
        insn = result.insn;
        // The crossing may have replaced or invalidated the stored fetch cache
        fetch_vaddr_page = tcc->fetch_vaddr_page;
        fetch_vf_offset = tcc->fetch_vf_offset;
        return result.status;
    }
    a.template read_memory_word<uint32_t, uint16_t>(faddr, tcc->fetch_pma_index, &insn);
    return fetch_status::success;
}

/// \brief Pre-decoded prediction of the next instruction, built while the
/// current one executes.
/// \details Holds the fall-through pc, the instruction word fetched at it,
/// and the resolved dispatch target, so the serial fetch chain (instruction
/// load, table load, indirect branch) overlaps instruction execution instead
/// of following it. It is only a prediction: the handler must verify it
/// before dispatching through it (execution status is plain success and the
/// architectural pc equals the predicted pc), and falls back to the generic
/// fetch tail otherwise. Handlers that can write guest memory never use it,
/// because a store over the fall-through bytes must be observed by the next
/// fetch.
template <typename STATE_ACCESS>
struct tc_predecode {
    uint64_t pc;
    uint32_t insn;
    bool hit;
    tc_handler_ptr<STATE_ACCESS> handler;
};

/// \brief Pre-decodes the fall-through successor of the current instruction.
/// \details Uses the same fetch primitives as the generic tail; performs
/// only side-effect-free host reads of guest RAM through the current valid
/// fetch mapping. The instruction length is a compile-time constant at every
/// call site (each handler serves exactly one encoding length), so the
/// rotation adds no length computation to the loop.
template <typename STATE_ACCESS>
static FORCE_INLINE tc_predecode<STATE_ACCESS> tc_predecode_next(const STATE_ACCESS a, uint64_t pc, uint64_t insn_len,
    uint64_t fetch_vaddr_page, i_state_access_fast_addr_t<STATE_ACCESS> fetch_vf_offset,
    tc_context<STATE_ACCESS> *tcc) {
    tc_predecode<STATE_ACCESS> next{};
    next.pc = pc + insn_len;
    next.hit = fetch_cache_is_hit(next.pc, fetch_vaddr_page);
    if (next.hit) [[likely]] {
        a.template read_memory_word<uint32_t, uint16_t>(next.pc + fetch_vf_offset, tcc->fetch_pma_index, &next.insn);
        next.handler = tc_jumptable<STATE_ACCESS>[insn_get_id(next.insn)];
    }
    return next;
}

#define TC_RETURN(st)                                                                                                  \
    do {                                                                                                               \
        tcc->pc = pc;                                                                                                  \
        tcc->mcycle = TC_MCYCLE_GET();                                                                                 \
        tcc->fetch_vaddr_page = fetch_vaddr_page;                                                                      \
        tcc->fetch_vf_offset = fetch_vf_offset;                                                                        \
        return (st);                                                                                                   \
    } while (0)

/// \brief Fetch continuation for everything except a fetch-cache hit.
/// \details Reached from handlers by tail call, so no call is reachable from
/// a handler's fetch tail and shrink-wrapping can keep handler hot paths
/// frameless. Handles translation, page crossing, and raising fetches, then
/// dispatches to the next handler.
template <typename STATE_ACCESS>
TC_CALLCONV static execute_status tc_fetch_miss(const STATE_ACCESS a, uint32_t /*insn*/ TC_HOT_PARAMS) {
    TC_ENTER();
    uint32_t tc_next_insn = 0;
#if TC_GLOBAL_REGS
    // tc_fetch_insn takes the fetch cache by reference and register globals
    // have no address, so proxy through locals on this cold path
    uint64_t proxy_vaddr_page = fetch_vaddr_page;
    i_state_access_fast_addr_t<STATE_ACCESS> proxy_vf_offset = fetch_vf_offset;
    for (;;) {
        if (tc_fetch_insn(a, pc, tc_next_insn, proxy_vaddr_page, proxy_vf_offset, tcc) == fetch_status::success)
            [[likely]] {
            break;
        }
        // The raising fetch consumed one cycle; execution continues from the
        // exception handler pc
        if (TC_TICK_ENDED()) [[unlikely]] {
            fetch_vaddr_page = proxy_vaddr_page;
            tc_reg_vf_offset = static_cast<uint64_t>(proxy_vf_offset);
            TC_RETURN(execute_status::success);
        }
    }
    fetch_vaddr_page = proxy_vaddr_page;
    tc_reg_vf_offset = static_cast<uint64_t>(proxy_vf_offset);
#else
    for (;;) {
        if (tc_fetch_insn(a, pc, tc_next_insn, fetch_vaddr_page, fetch_vf_offset, tcc) == fetch_status::success)
            [[likely]] {
            break;
        }
        // The raising fetch consumed one cycle; execution continues from the
        // exception handler pc
        if (TC_TICK_ENDED()) [[unlikely]] {
            TC_RETURN(execute_status::success);
        }
    }
#endif
    TC_SYNC();
    TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS);
}

// Each handler pre-decodes its fall-through successor (when its class allows),
// executes its instruction, performs the same status handling as the stock
// post-switch code, advances mcycle, and dispatches to the next handler with a
// guaranteed tail call, through the verified prediction when it holds and
// through the generic fetch tail otherwise. The fixed argument list pins the
// interpreter's hot state to the same registers at every handler boundary.
// Dispatch is deliberately replicated per handler so each indirect branch site
// keeps its own target history in the branch predictor, and every non-hit
// fetch leaves by tail call so the hot path reaches no call.
#define TC_CASE(NAME, PRELOAD, LEN, EXPR)                                                                              \
    template <typename STATE_ACCESS>                                                                                   \
    TC_CALLCONV static execute_status tc_handler_##NAME(const STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS) {           \
        TC_ENTER();                                                                                                    \
        [[maybe_unused]] tc_predecode<STATE_ACCESS> tc_next{};                                                         \
        if constexpr (TC_PRELOAD_ENABLED != 0 && (PRELOAD) != 0) {                                                     \
            tc_next = tc_predecode_next(a, pc, (LEN), fetch_vaddr_page, fetch_vf_offset, tcc);                         \
        }                                                                                                              \
        const execute_status status = (EXPR);                                                                          \
        if (status > execute_status::success) [[unlikely]] {                                                           \
            fetch_vaddr_page = ensure_fetch_cache_miss(pc);                                                            \
            tcc->fetch_vaddr_page = fetch_vaddr_page;                                                                  \
            if (status >= execute_status::success_and_serve_interrupts) [[unlikely]] {                                 \
                --tc_remaining;                                                                                        \
                TC_RETURN(status);                                                                                     \
            }                                                                                                          \
        }                                                                                                              \
        if (TC_TICK_ENDED()) [[unlikely]] {                                                                            \
            TC_RETURN(execute_status::success);                                                                        \
        }                                                                                                              \
        /* Straight-line handlers (class 2) reach pc == tc_next.pc whenever                                            \
           execution status is plain success, so only conditional branches                                             \
           (class 1) need the pc comparison */                                                                         \
        if constexpr (TC_PRELOAD_ENABLED != 0 && (PRELOAD) == 2) {                                                     \
            if (status == execute_status::success && tc_next.hit) [[likely]] {                                         \
                TC_SYNC();                                                                                             \
                TC_MUSTTAIL return tc_next.handler(a, tc_next.insn TC_HOT_ARGS);                                       \
            }                                                                                                          \
        } else if constexpr (TC_PRELOAD_ENABLED != 0 && (PRELOAD) == 1) {                                              \
            if (status == execute_status::success && tc_next.hit && pc == tc_next.pc) [[likely]] {                     \
                TC_SYNC();                                                                                             \
                TC_MUSTTAIL return tc_next.handler(a, tc_next.insn TC_HOT_ARGS);                                       \
            }                                                                                                          \
        }                                                                                                              \
        if (fetch_cache_is_hit(pc, fetch_vaddr_page)) [[likely]] {                                                     \
            uint32_t tc_next_insn = 0;                                                                                 \
            a.template read_memory_word<uint32_t, uint16_t>(pc + fetch_vf_offset, tcc->fetch_pma_index,                \
                &tc_next_insn);                                                                                        \
            TC_SYNC();                                                                                                 \
            TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS);     \
        }                                                                                                              \
        TC_SYNC();                                                                                                     \
        TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);                                           \
    }
#include "interpret-tc-cases.inc"
#undef TC_CASE
#undef TC_RETURN

/// \brief Tail-call variant of the interpreter hot loop; same observable behavior as interpret_loop().
template <typename STATE_ACCESS>
static NO_INLINE execute_status interpret_loop_tc_body(const STATE_ACCESS a, uint64_t mcycle_end, uint64_t mcycle) {
    uint64_t pc = a.read_pc();
    if ((pc & 1) != 0) {
        pc = raise_exception(a, pc, MCAUSE_INSN_ADDRESS_MISALIGNED, pc);
    }

    tc_context<STATE_ACCESS> tcc{};
    tcc.mcycle_end = mcycle_end;
    tcc.fetch_vaddr_page = ensure_fetch_cache_miss(pc);
    tcc.fetch_pma_index = TLB_INVALID_PMA_INDEX;

    while (mcycle < mcycle_end) {
        if (rtc_is_tick(mcycle)) {
            set_rtc_interrupt(a, mcycle);
            if constexpr (is_an_i_interactive_state_access_v<STATE_ACCESS>) {
                a.poll_external_interrupts(mcycle, mcycle);
            }
        }

        pc = raise_interrupt_if_any(a, pc, tcc.fetch_vaddr_page);

#ifndef NDEBUG
        assert_no_brk(a);
#endif

        const uint64_t mcycle_tick_end = mcycle + std::min(mcycle_end - mcycle, RTC_FREQ_DIV - (mcycle % RTC_FREQ_DIV));
        tcc.mcycle_tick_end = mcycle_tick_end;

        execute_status status = execute_status::success;
        while (mcycle < mcycle_tick_end) {
            uint32_t insn = 0;
            if (fetch_insn(a, pc, insn, tcc.fetch_vaddr_page, tcc.fetch_vf_offset, tcc.fetch_pma_index) ==
                fetch_status::success) [[likely]] {
#if TC_GLOBAL_REGS
                cartesi::tc_reg_pc = pc;
                cartesi::tc_remaining = mcycle_tick_end - mcycle;
                cartesi::tcc = &tcc;
                cartesi::fetch_vaddr_page = tcc.fetch_vaddr_page;
                cartesi::tc_reg_vf_offset = static_cast<uint64_t>(tcc.fetch_vf_offset);
                status = tc_jumptable<STATE_ACCESS>[insn_get_id(insn)](a, insn);
#else
                status = tc_jumptable<STATE_ACCESS>[insn_get_id(insn)](a, insn, pc, mcycle_tick_end - mcycle, &tcc,
                    tcc.fetch_vaddr_page, tcc.fetch_vf_offset);
#endif
                pc = tcc.pc;
                mcycle = tcc.mcycle;
                break;
            }
            // Fetch raised an exception: it consumes one cycle and execution continues
            // from the exception handler pc
            ++mcycle;
        }

        if (status >= execute_status::success_and_yield) [[unlikely]] {
            // Got an interruption that must be handled externally
            a.write_pc(pc);
            a.write_mcycle(mcycle);
            return status;
        }
        // Else status is success (tick or mcycle_end reached) or
        // success_and_serve_interrupts (outer loop serves interrupts): continue
    }

    // Commit machine state
    a.write_pc(pc);
    a.write_mcycle(mcycle);
    return execute_status::success;
}

#if TC_GLOBAL_REGS
/// \brief Snapshot of the six reserved registers' values.
struct tc_saved_regs {
    uint64_t r[5];
};

/// \brief Reads the reserved registers through asm the compiler cannot analyze.
/// \details Plain reads and writes of the register globals are not enough:
/// Clang assumes -ffixed registers cannot change across calls and deletes a
/// same-value save/restore pair around the interpreter run, which corrupts
/// the caller's callee-saved registers.
static FORCE_INLINE tc_saved_regs tc_save_pinned_regs() {
    tc_saved_regs s;
    asm volatile("mov %0, x23\n\tmov %1, x24\n\tmov %2, x25\n\tmov %3, x26\n\tmov %4, x27"
        : "=r"(s.r[0]), "=r"(s.r[1]), "=r"(s.r[2]), "=r"(s.r[3]), "=r"(s.r[4])
        :
        : "memory");
    return s;
}

/// \brief Writes the reserved registers through asm the compiler cannot analyze.
static FORCE_INLINE void tc_restore_pinned_regs(const tc_saved_regs &s) {
    asm volatile("mov x23, %0\n\tmov x24, %1\n\tmov x25, %2\n\tmov x26, %3\n\tmov x27, %4"
        :
        : "r"(s.r[0]), "r"(s.r[1]), "r"(s.r[2]), "r"(s.r[3]), "r"(s.r[4])
        : "memory");
}
#endif

template <typename STATE_ACCESS>
static execute_status interpret_loop_tc(const STATE_ACCESS a, uint64_t mcycle_end, uint64_t mcycle) {
#if TC_GLOBAL_REGS
    // The reserved registers belong to the interpreter only while it runs.
    // They are call-saved in the standard convention, so the caller may hold
    // live values in them; preserve those values across the run, including
    // when an exception unwinds out of the interpreter.
    const auto restore = scope_exit([saved = tc_save_pinned_regs()] { tc_restore_pinned_regs(saved); });
#endif
    return interpret_loop_tc_body(a, mcycle_end, mcycle);
}

/// \brief Entry point for interpret.cpp, which cannot see the machinery above.
execute_status interpret_loop_tc_run(const state_access a, uint64_t mcycle_end, uint64_t mcycle) {
    return interpret_loop_tc(a, mcycle_end, mcycle);
}

} // namespace cartesi
