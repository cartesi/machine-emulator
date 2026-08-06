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

#include <csignal>
#include <cstring>
#include <new>
#if defined(TC_JIT) && TC_JIT
#include <sys/mman.h>
#endif

namespace cartesi {

#include "interpret-tc-abi.hpp"

#if TC_JIT_COVERAGE
#define TC_JIT_COVER_ENTER() (tcc->jit_enter_rem = tc_remaining)
#define TC_JIT_COVER_EXIT() (tc_jit_storage.insns += tcc->jit_enter_rem - tc_remaining)
#else
#define TC_JIT_COVER_ENTER() ((void) 0)
#define TC_JIT_COVER_EXIT() ((void) 0)
#endif


#if TC_JIT
/// \brief Which operand of the recorded instruction a patch site carries.
/// \details The names are the hole symbols of interpret-tc-stencils.cpp with
/// their tc_h_ prefix stripped; the generated table refers to them by name, so
/// a hole that appears in the stencils without a case here is a build error
/// rather than a silently unpatched immediate.
enum tc_hole_kind : uint8_t {
    TC_HOLE_INSN, ///< The recorded instruction word
    // Register fields, each carrying a byte offset rather than an index. There
    // is one per getter, not one per role, so that the JIT can fill a hole by
    // calling the getter it is named for (tc_jit_hole_value).
    TC_HOLE_RD,
    TC_HOLE_RS1,
    TC_HOLE_RS2,
    TC_HOLE_C_RD_RS2,
    TC_HOLE_C_RS1,
    TC_HOLE_C_RS2,
    // Immediates, likewise one per encoding format
    TC_HOLE_IMM_I,
    TC_HOLE_IMM_IU,
    TC_HOLE_IMM_U,
    TC_HOLE_IMM_B,
    TC_HOLE_IMM_J,
    TC_HOLE_IMM_S,
    TC_HOLE_IMM_CJ,
    TC_HOLE_IMM_CBEQZ,
    TC_HOLE_IMM_CLCS,
    TC_HOLE_IMM_CICB,
    TC_HOLE_IMM_CICBSE,
    TC_HOLE_IMM_CLW,
    TC_HOLE_IMM_CLSB,
    TC_HOLE_IMM_CLSH,
    TC_HOLE_IMM_CIW,
    TC_HOLE_IMM_CADDI16SP,
    TC_HOLE_IMM_CLUI,
    TC_HOLE_IMM_CLDSP,
    TC_HOLE_IMM_CLWSP,
    TC_HOLE_IMM_CSDSP,
    TC_HOLE_IMM_CSWSP,
    // Not instruction fields at all
    TC_HOLE_NEXT_DELTA, ///< How far the recorded successor lies from this step
    TC_HOLE_K,       ///< Cycles this block owes once this step has run
    TC_HOLE_CONT,    ///< The next stencil, or nothing when it is the next byte
    TC_HOLE_EXIT,    ///< Where this step leaves for the interpreter
};

/// \brief How a hole is written into the machine code.
enum tc_patch_kind : uint8_t {
    TC_PATCH_ABS32,  ///< 32-bit absolute, zero-extended (immediates)
    TC_PATCH_ABS32S, ///< 32-bit absolute, sign-extended (addressing displacements)
    TC_PATCH_ABS64,  ///< 64-bit absolute
    TC_PATCH_REL32,  ///< 32-bit displacement from the end of the field (branches)
};

/// \brief One patch site inside a stencil body.
struct tc_stencil_hole {
    uint16_t off;        ///< Where in the body, in bytes
    tc_hole_kind hole;   ///< What value goes there
    tc_patch_kind patch; ///< How it is encoded
    int64_t addend;      ///< Contribution the relocation carried
};

/// \brief Where one stencil's code and patch sites live in the generated blobs.
struct tc_stencil_desc {
    uint32_t code_off;
    uint16_t size;
    uint16_t hole_off;
    uint16_t nholes;
};

#include "interpret-tc-stencils.inc"

/// \brief Each stencil's row in the generated table, by case name.
enum tc_stencil_index : uint16_t {
#define X(IDX, NAME) TC_STENCIL_INDEX_##NAME = (IDX),
    TC_STENCIL_LIST(X)
#undef X
};

// A stencil is only relocatable into a chain compiled against the identical
// contract: it addresses the context by offset and expects the shape's
// registers to hold what they hold. Mismatched, it would run and be silently
// wrong, so the shape it was built against is checked rather than assumed.
static_assert(TC_STENCIL_ABI_CONTEXT_SIZE == sizeof(tc_context<state_access>),
    "stencils were built against a different loop context");
static_assert(TC_STENCIL_ABI_OFF_PC == offsetof(tc_context<state_access>, pc));
static_assert(TC_STENCIL_ABI_OFF_MCYCLE == offsetof(tc_context<state_access>, mcycle));
static_assert(TC_STENCIL_ABI_OFF_TICK_END == offsetof(tc_context<state_access>, mcycle_tick_end));
static_assert(TC_STENCIL_ABI_OFF_FETCH_PAGE == offsetof(tc_context<state_access>, fetch_vaddr_page));
static_assert(TC_STENCIL_ABI_OFF_FETCH_PMA == offsetof(tc_context<state_access>, fetch_pma_index));
static_assert(TC_STENCIL_ABI_GLOBAL_REGS == TC_GLOBAL_REGS, "stencils were built for a different register shape");
static_assert(TC_STENCIL_ABI_PAGE_SEGMENT == TC_PAGE_SEGMENT, "stencils were built for a different fetch shape");
static_assert(TC_STENCIL_ABI_PRESERVE_NONE == TC_USE_PRESERVE_NONE, "stencils were built for a different convention");

#include "interpret-tc-jit.hpp"

/// \brief Compiles a finished recording, returning its entry point or nullptr.
/// \details Defined after the handler table it exits into.
static const void *tc_jit_compile(tc_context<state_access> *c, const tc_online_state::trace &t);
#endif // TC_JIT

#if TC_ONLINE
#if TC_AOT
#error "TC_ONLINE and TC_AOT flush rules conflict; enable one at a time"
#endif

static THREAD_LOCAL tc_online_state tc_online_storage;

/// \brief Membership test in the fixed installed-head set.
static FORCE_INLINE bool tc_online_installed(const tc_online_state *o, uint64_t pc) {
    uint32_t s = (static_cast<uint32_t>(pc) >> 1) & (tc_online_state::set_slots - 1);
    while (o->installed_set[s] != 0) {
        if (o->installed_set[s] == pc) {
            return true;
        }
        s = (s + 1) & (tc_online_state::set_slots - 1);
    }
    return false;
}

/// \brief Inserts into the fixed installed-head set (capacity guaranteed by flush).
static FORCE_INLINE void tc_online_insert(tc_online_state *o, uint64_t pc) {
    uint32_t s = (static_cast<uint32_t>(pc) >> 1) & (tc_online_state::set_slots - 1);
    while (o->installed_set[s] != 0 && o->installed_set[s] != pc) {
        s = (s + 1) & (tc_online_state::set_slots - 1);
    }
    o->installed_set[s] = pc;
}

/// \brief Debug event print, first 200 events only, when TC_ONLINE_DEBUG is set.
static NO_INLINE void tc_online_debug(const char *what, uint64_t pc, uint64_t extra) {
    static THREAD_LOCAL int budget = -1;
    if (budget < 0) {
        budget = (std::getenv("TC_ONLINE_DEBUG") != nullptr) ? 200 : 0;
    }
    if (budget > 0) {
        --budget;
        std::fprintf(stderr, "tc-online: %s pc %llx extra %llu\n", what, static_cast<unsigned long long>(pc),
            static_cast<unsigned long long>(extra));
    }
}

/// \brief Prints recorder statistics at exit when TC_ONLINE_STATS is set.
__attribute__((destructor)) static void tc_online_report() {
    if (std::getenv("TC_ONLINE_STATS") == nullptr) {
        return;
    }
    const auto &o = tc_online_storage;
    std::fprintf(stderr, "tc-online: installed %llu aborted %llu flushes %llu live %u\n",
        static_cast<unsigned long long>(o.installed), static_cast<unsigned long long>(o.aborted),
        static_cast<unsigned long long>(o.flushes), static_cast<unsigned>(o.ntraces));
}

/// \brief Discards all installed traces and profiling progress (pool full).
template <typename STATE_ACCESS>
static void tc_online_flush(tc_context<STATE_ACCESS> *c) {
    tc_online_state *o = c->online;
    o->ntraces = 0;
    ++o->flushes;
    tc_online_debug("flush", 0, o->flushes);
    for (auto &s : o->installed_set) {
        s = 0;
    }
    for (auto &p : c->hot.head_pc) {
        p = UINT64_MAX;
    }
    for (auto &h : c->hot.hotcount) {
        h = TC_HOT_RESET;
    }
#if TC_JIT
    // The code cache is bump-allocated and flushed with the pool it serves, so
    // no compiled trace can outlive the head table entry that names it
    ++tc_jit_storage.flushes;
    tc_jit_storage.used = 0;
    for (auto &f : c->hot.head_fn) {
        f = nullptr;
    }
#endif
    // Penalties survive the flush: heads that never produce installable
    // recordings would otherwise churn again after every flush
}

/// \brief Ends the active recording, installing or penalizing its head.
template <typename STATE_ACCESS>
static void tc_online_finish(tc_context<STATE_ACCESS> *c, int32_t cycle) {
    tc_online_state *o = c->online;
    o->recording = false;
    auto &t = o->pool[o->ntraces];
    tc_online_debug(t.len < tc_online_state::min_len ? "abort" : "install", t.head, t.len);
    const uint32_t h = (static_cast<uint32_t>(t.head) >> 1) & (TC_HEAD_SLOTS - 1);
    if (t.len < tc_online_state::min_len) {
        ++o->aborted;
        if (o->penalty_pc[h] == t.head) {
            ++o->penalty[h];
        } else {
            o->penalty_pc[h] = t.head;
            o->penalty[h] = 1;
        }
        return;
    }
    t.cycle = cycle;
#if TC_JIT
    // A recording that cannot be compiled is worth nothing: without a backend
    // it would sit in the head table costing a probe and returning nothing.
    // Penalize its head so the recorder stops trying, exactly as for a
    // recording that came out too short.
    const void *entry = tc_jit_compile(c, t);
    if (entry == nullptr) {
        ++o->aborted;
        if (o->penalty_pc[h] == t.head) {
            ++o->penalty[h];
        } else {
            o->penalty_pc[h] = t.head;
            o->penalty[h] = 1;
        }
        return;
    }
    c->hot.head_fn[h] = entry;
    c->hot.head_key[h] = c->jit_key;
    t.entry = entry;
    t.key = c->jit_key;
#endif
    c->hot.head_pc[h] = t.head;
    tc_online_insert(o, t.head);
    ++o->installed;
    ++o->ntraces;
    if (o->ntraces == tc_online_state::max_traces) {
        tc_online_flush(c);
    }
}

/// \brief Starts recording at a hot head unless it is installed or blacklisted.
template <typename STATE_ACCESS>
static void tc_online_begin(tc_context<STATE_ACCESS> *c, uint64_t pc) {
    tc_online_state *o = c->online;
    const uint32_t h = (static_cast<uint32_t>(pc) >> 1) & (TC_HEAD_SLOTS - 1);
    if (o->recording || tc_online_installed(o, pc) ||
        (o->penalty_pc[h] == pc && o->penalty[h] >= tc_online_state::max_penalty)) {
        return;
    }
    auto &t = o->pool[o->ntraces];
    t.head = pc;
    t.len = 0;
    t.cycle = -1;
    o->recording = true;
    tc_online_debug("begin", pc, o->ntraces);
}

/// \brief Appends the instruction about to execute to the active recording.
/// \details The previous entry's successor is this pc, whatever happened in
/// between; the recording ends when execution leaves the head's page, closes
/// a cycle over a recorded address, or fills the slot.
template <typename STATE_ACCESS>
static void tc_online_record(tc_context<STATE_ACCESS> *c, uint64_t pc, uint32_t insn) {
    tc_online_state *o = c->online;
    auto &t = o->pool[o->ntraces];
    if (t.len > 0) {
        t.entries[t.len - 1].next_pc = pc;
        for (uint32_t i = 0; i < t.len; ++i) {
            if (t.entries[i].vaddr == pc) {
                tc_online_finish(c, static_cast<int32_t>(i));
                return;
            }
        }
        if ((pc >> 12) != (t.head >> 12)) {
            tc_online_finish(c, -1);
            return;
        }
        if (t.len == tc_online_state::max_len) {
            tc_online_finish(c, -1);
            return;
        }
    }
    t.entries[t.len] = tc_online_entry{pc, 0, insn};
    ++t.len;
}
/// \brief Leaves the chain when a hot loop requests recording. The request is
/// handled by the outer loop, keeping all recorder calls out of handlers.
#define TC_ONLINE_TRIP_RETURN()                                                                                        \
    do {                                                                                                               \
        if (tcc->online_trip) [[unlikely]] {                                                                           \
            TC_RETURN(execute_status::success);                                                                        \
        }                                                                                                              \
    } while (0)
#define TC_ONLINE_CALL_TRIP_RETURN()                                                                                   \
    do {                                                                                                               \
        if (tcc->online_trip) [[unlikely]] {                                                                           \
            --tc_remaining;                                                                                            \
            TC_RETURN(execute_status::success);                                                                        \
        }                                                                                                              \
    } while (0)
#else
#define TC_ONLINE_TRIP_RETURN() ((void) 0)
#define TC_ONLINE_CALL_TRIP_RETURN() ((void) 0)
#endif // TC_ONLINE

/// \brief Probes the trace-head table and updates the hotcount at a profiling
/// site, returning the installed trace function on a head hit (never under
/// the plain shell, whose head table stays empty; entries counts hits so the
/// probe is not dead). Defined unconditionally so discarded constexpr
/// branches can name it; the body only instantiates under TC_JIT_SHELL.
#if TC_JIT
/// \brief The host page a virtual pc currently resolves to, or 0 for none.
/// \details This is what a compiled trace is keyed by, and the code TLB is
/// already the thing that knows it. A trace holds the instructions that were at
/// its virtual pc rather than a way to fetch them, so what has to still hold at
/// entry is that the pc names the same memory; comparing host pages says
/// exactly that, in the terms the interpreter's own fetch path maintains.
///
/// Keying this way rather than on the address space is what lets traces survive
/// a multitasking guest. The same physical page mapped into two processes is
/// one page, so a trace in it is valid in both and a context switch costs
/// nothing. Invalidation is likewise self-correcting instead of permanent:
/// flushing the TLB makes this consult miss, the trace is not entered that
/// once, the interpreter refills the entry on its next fetch, and entries
/// resume. Nothing needs to count invalidation events, because the structure
/// that gets invalidated is the one being asked.
template <typename STATE_ACCESS>
static FORCE_INLINE uint64_t tc_jit_code_page(const STATE_ACCESS a, uint64_t vpc) {
    const uint64_t slot = tlb_slot_index(vpc);
    const uint64_t page = vpc & ~PAGE_OFFSET_MASK;
    if (a.template read_tlb_vaddr_page<TLB_CODE>(slot) != page) {
        return 0;
    }
    return static_cast<uint64_t>(page + a.template read_tlb_vf_offset<TLB_CODE>(slot));
}
#endif

template <typename STATE_ACCESS>
static FORCE_INLINE const void *tc_hook_site(const STATE_ACCESS a, tc_context<STATE_ACCESS> *c, uint64_t vpc,
    uint16_t weight) {
    const uint32_t h = (static_cast<uint32_t>(vpc) >> 1) & (TC_HEAD_SLOTS - 1);
    const void *fn = nullptr;
    if (c->hot.head_pc[h] == vpc) [[unlikely]] {
        ++c->hot.entries;
#if TC_JIT
        // Consult the TLB only here, where a head actually matched, so the
        // common path of the hook does not pay for it
        if (c->hot.head_key[h] != 0 && c->hot.head_key[h] == tc_jit_code_page(a, vpc)) {
            fn = c->hot.head_fn[h];
#if TC_JIT_COVERAGE
            if (fn != nullptr) {
                ++tc_jit_storage.per_head[h];
                tc_jit_storage.per_head_pc[h] = vpc;
            }
#endif
            tc_jit_storage.entered += (fn != nullptr) ? 1 : 0;
        } else {
            ++tc_jit_storage.stale;
        }
#elif TC_AOT
        fn = c->hot.head_fn[h];
#endif
    }
    (void) a;
    c->hot.hotcount[h] -= weight;
    if (static_cast<int16_t>(c->hot.hotcount[h]) <= 0) [[unlikely]] {
        c->hot.hotcount[h] = TC_HOT_RESET;
#if TC_ONLINE
        // Recorder setup contains calls and must stay out of the handler:
        // request a chain exit and let the outer loop start it.
        c->online_trip_pc = vpc;
        c->online_trip_weight = weight;
        c->online_trip = true;
#endif
    }
    return fn;
}
#if TC_JIT_SHELL
// Calls hook unconditionally at the callee; the expression yields the status.
// Under TC_AOT a head hit does not dispatch from here (the call's own status
// handling has not run yet); the back-edge sites carry the dispatch.
#define TC_HOOK_CALL(expr)                                                                                             \
    ({                                                                                                                 \
        const execute_status tc_call_status = (expr);                                                                  \
        if (tc_call_status == execute_status::success) {                                                               \
            (void) tc_hook_site(a, tcc, pc_to_virtual(a, pc), 1);                                                                           \
            TC_ONLINE_CALL_TRIP_RETURN();                                                                              \
        }                                                                                                              \
        tc_call_status;                                                                                                \
    })
#else
#define TC_HOOK_CALL(expr) (expr)
#endif

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
template <typename STATE_ACCESS>
struct tc_walk_result {
    fetch_status status;
    i_state_access_fast_addr_t<STATE_ACCESS> pc;
    i_state_access_fast_addr_t<STATE_ACCESS> vf_offset;
};

/// \brief Outlined page-table walk for the tail-call fetch path (true code TLB miss).
/// \details Cold, so returning the mapping by value through memory is fine.
/// On success, pma_index is stored into the tc_context and the new mapping
/// offset is returned (the caller deposits it after committing); on
/// exception, fetch_translate_pc_slow updates tcc->fetch_vaddr_page (the
/// fetch-cache invalidation) through the reference it receives.
template <typename STATE_ACCESS>
[[gnu::noinline]] static tc_walk_result<STATE_ACCESS> tc_fetch_translate_pc_walk(const STATE_ACCESS a,
    i_state_access_fast_addr_t<STATE_ACCESS> pc, uint64_t vaddr, tc_context<STATE_ACCESS> *tcc) {
    i_state_access_fast_addr_t<STATE_ACCESS> vf_offset{};
    uint64_t pma_index{};
    const fetch_status status = fetch_translate_pc_slow(a, pc, vaddr, vf_offset, pma_index, tcc->fetch_vaddr_page);
    if (status == fetch_status::success) [[likely]] {
        tcc->fetch_pma_index = pma_index;
    }
    return {status, pc, vf_offset};
}

/// \brief TLB consult for the tail-call fetch path; mirrors fetch_translate_pc
/// but keeps only the TLB-hit path inline, outlining the walk.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status tc_fetch_translate_pc(const STATE_ACCESS a,
    i_state_access_fast_addr_t<STATE_ACCESS> &pc, uint64_t vaddr,
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
        const tc_walk_result<STATE_ACCESS> result = tc_fetch_translate_pc_walk(a, pc, vaddr, tcc);
        pc = result.pc;
        if (result.status == fetch_status::success) [[likely]] {
            vf_offset = result.vf_offset;
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
template <typename STATE_ACCESS>
struct tc_crossing_result {
    fetch_status status;
    uint32_t insn;
    i_state_access_fast_addr_t<STATE_ACCESS> pc;
};
static_assert(sizeof(tc_crossing_result<state_access>) <= 16);

/// \brief Outlined fetch for a pc crossing a page boundary (rare: last 2 bytes of a page).
/// \details pc arrives as the valid fast address of the crossing
/// instruction; on an uncompressed crossing the cache moves to the next
/// page and pc is re-encoded with the new deposit, exactly as in
/// fetch_insn.
template <typename STATE_ACCESS>
[[gnu::noinline]] static tc_crossing_result<STATE_ACCESS> tc_fetch_insn_crossing(const STATE_ACCESS a, uint64_t vpc,
    i_state_access_fast_addr_t<STATE_ACCESS> pc, tc_context<STATE_ACCESS> *tcc) {
    uint16_t insn16 = 0;
    a.template read_memory_word<uint16_t>(pc, tcc->fetch_pma_index, &insn16);
    uint32_t insn = insn16;
    if (insn_is_uncompressed(insn)) [[unlikely]] {
        const uint64_t vpc2 = vpc + 2;
        i_state_access_fast_addr_t<STATE_ACCESS> pc2_vf_offset{};
        uint64_t pc2_pma_index{};
        if (fetch_translate_pc(a, pc, vpc2, pc2_vf_offset, pc2_pma_index, tcc->fetch_vaddr_page) ==
            fetch_status::exception) [[unlikely]] {
            return {fetch_status::exception, 0, pc};
        }
        a.write_fetch_vf_offset(pc2_vf_offset);
        pc = vpc + pc2_vf_offset;
        tcc->fetch_vaddr_page = vpc2 + pc2_vf_offset;
        tcc->fetch_pma_index = pc2_pma_index;
        a.template read_memory_word<uint16_t>(tcc->fetch_vaddr_page, tcc->fetch_pma_index, &insn16);
        insn |= static_cast<uint32_t>(insn16) << 16;
    }
    return {fetch_status::success, insn, pc};
}

/// \brief Fetch for the tail-call dispatch tail; mirrors fetch_insn with the
/// fetch cache in the tc_context. The code-page-cache hit and the TLB consult
/// stay inline in each handler; only the page-table walk and the boundary
/// crossing are out of line.
template <typename STATE_ACCESS>
static FORCE_INLINE fetch_status tc_fetch_insn(const STATE_ACCESS a, i_state_access_fast_addr_t<STATE_ACCESS> &pc,
    uint32_t &insn, i_state_access_fast_addr_t<STATE_ACCESS> &fetch_vaddr_page, tc_context<STATE_ACCESS> *tcc) {
    if (fetch_cache_is_hit(pc, fetch_vaddr_page)) [[likely]] {
        a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index, &insn);
        return fetch_status::success;
    }
    // Decode the architectural pc through the same deposit that encoded it
    const uint64_t vpc = pc_to_virtual(a, pc);
    const uint64_t vpc_page = tlb_addr_page(vpc);
    if (pc_to_fast(a, vpc_page) != fetch_vaddr_page) [[likely]] {
        i_state_access_fast_addr_t<STATE_ACCESS> pc_vf_offset{};
        uint64_t pc_pma_index{};
        if (tc_fetch_translate_pc(a, pc, vpc, pc_vf_offset, pc_pma_index, tcc) == fetch_status::exception)
            [[unlikely]] {
            // The slow path invalidated the stored fetch cache with the exception handler pc
            fetch_vaddr_page = tcc->fetch_vaddr_page;
            return fetch_status::exception;
        }
        // Deposit the new mapping and re-encode pc and the tag with it
        a.write_fetch_vf_offset(pc_vf_offset);
        pc = vpc + pc_vf_offset;
        fetch_vaddr_page = pc - (vpc & PAGE_OFFSET_MASK);
        tcc->fetch_vaddr_page = fetch_vaddr_page;
        tcc->fetch_pma_index = pc_pma_index;
    }
    if (((~vpc & PAGE_OFFSET_MASK) >> 1) == 0) [[unlikely]] {
        const tc_crossing_result<STATE_ACCESS> result = tc_fetch_insn_crossing(a, vpc, pc, tcc);
        pc = result.pc;
        insn = result.insn;
        // The crossing may have replaced or invalidated the stored fetch cache
        fetch_vaddr_page = tcc->fetch_vaddr_page;
        return result.status;
    }
    a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index, &insn);
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
    i_state_access_fast_addr_t<STATE_ACCESS> pc;
    uint32_t insn;
    bool hit;
    tc_handler_ptr<STATE_ACCESS> handler;
};

#if TC_PAGE_SEGMENT
/// \brief Number of fall-through fetches from pc that provably stay within
/// the fetchable region of pc's page.
/// \details A fetch at page offset o reads bytes o..o+3, so it is safe iff
/// o <= PAGE_OFFSET_MASK - 3 (the same bound fetch_cache_is_hit enforces
/// for 2-byte-aligned pc), and successors advance by at most 4 bytes each.
/// Negative when pc itself sits in the crossing region; callers rely on
/// signed arithmetic throughout.
template <typename FAST_ADDR>
static FORCE_INLINE int64_t tc_seg_allowance(FAST_ADDR pc) {
    // Valid on the fast encoding because state_access's mapping offsets
    // are page-aligned (host memory comes from page-aligned mappings),
    // preserving the page offset bits
    return (static_cast<int64_t>(PAGE_OFFSET_MASK) - 3 - static_cast<int64_t>(pc & PAGE_OFFSET_MASK)) >> 2;
}

/// \brief Re-establishes the segment invariant after pc may have left the
/// fall-through path (taken branches, raises, new mappings).
/// \details Tighten-only: the countdown and its base move together by the
/// same amount, preserving the mcycle materialization identity, and the
/// bound never extends, so it can never pass the true tick end. Chains
/// that tighten to nothing exit early and re-derive in the outer loop.
#define TC_SEG_TIGHTEN()                                                                                               \
    do {                                                                                                               \
        const int64_t tc_seg_nb = tc_seg_allowance(pc);                                                                \
        const int64_t tc_seg_d = static_cast<int64_t>(tc_remaining) - tc_seg_nb;                                       \
        if (tc_seg_d > 0) {                                                                                            \
            TC_CHAIN_END -= static_cast<uint64_t>(tc_seg_d);                                                           \
            tc_remaining = static_cast<uint64_t>(tc_seg_nb);                                                           \
        }                                                                                                              \
    } while (0)

// The pre-decode reads one instruction ahead of retirement, so its guard is
// the countdown itself: entering with at least one more instruction to
// retire proves the fall-through fetch is within the segment budget (the
// budget covers one fetch past the last retirement for exactly this read).
#define TC_PREDECODE_SAFE(LEN) (static_cast<int64_t>(tc_remaining) >= 1)
#else
#define TC_SEG_TIGHTEN() ((void) 0)
#define TC_PREDECODE_SAFE(LEN) fetch_cache_is_hit(pc + (LEN), TC_FETCH_TAG)
#endif

/// \brief Pre-decodes the fall-through successor of the current instruction.
/// \details Uses the same fetch primitives as the generic tail; performs
/// only side-effect-free host reads of guest RAM through the current valid
/// fetch mapping. The instruction length is a compile-time constant at every
/// call site (each handler serves exactly one encoding length), so the
/// rotation adds no length computation to the loop. The caller supplies the
/// page-safety predicate for the read (see TC_PREDECODE_SAFE).
template <typename STATE_ACCESS>
static FORCE_INLINE tc_predecode<STATE_ACCESS> tc_predecode_next(const STATE_ACCESS a,
    i_state_access_fast_addr_t<STATE_ACCESS> pc, uint64_t insn_len, bool safe, tc_context<STATE_ACCESS> *tcc) {
    tc_predecode<STATE_ACCESS> next{};
    next.pc = pc + insn_len;
    next.hit = safe;
    if (next.hit) [[likely]] {
        a.template read_memory_word<uint32_t, uint16_t>(next.pc, tcc->fetch_pma_index, &next.insn);
        next.handler = tc_jumptable<STATE_ACCESS>[insn_get_id(next.insn)];
    }
    return next;
}

#define TC_RETURN(st)                                                                                                  \
    do {                                                                                                               \
        tcc->pc = pc;                                                                                                  \
        tcc->mcycle = TC_MCYCLE_GET();                                                                                 \
        TC_FETCH_TAG_SYNC();                                                                                           \
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
    // have no address, so proxy through a local on this cold path
    auto proxy_fetch_page = TC_FETCH_TAG;
    for (;;) {
        if (tc_fetch_insn(a, pc, tc_next_insn, proxy_fetch_page, tcc) == fetch_status::success) [[likely]] {
            break;
        }
        // The raising fetch consumed one cycle; execution continues from the
        // exception handler pc
        if (TC_TICK_ENDED()) [[unlikely]] {
            tc_reg_fetch_page = static_cast<uint64_t>(proxy_fetch_page);
            TC_RETURN(execute_status::success);
        }
    }
    tc_reg_fetch_page = static_cast<uint64_t>(proxy_fetch_page);
#elif TC_PAGE_SEGMENT
    // The demoted fetch tag lives in the context; proxy it through a local
    // for tc_fetch_insn's reference parameter on this cold path
    auto proxy_fetch_page = tcc->fetch_vaddr_page;
    for (;;) {
        if (tc_fetch_insn(a, pc, tc_next_insn, proxy_fetch_page, tcc) == fetch_status::success) [[likely]] {
            break;
        }
        // The raising fetch consumed one cycle; execution continues from the
        // exception handler pc
        if (TC_TICK_ENDED()) [[unlikely]] {
            tcc->fetch_vaddr_page = proxy_fetch_page;
            TC_RETURN(execute_status::success);
        }
    }
    tcc->fetch_vaddr_page = proxy_fetch_page;
#else
    for (;;) {
        if (tc_fetch_insn(a, pc, tc_next_insn, fetch_vaddr_page, tcc) == fetch_status::success) [[likely]] {
            break;
        }
        // The raising fetch consumed one cycle; execution continues from the
        // exception handler pc
        if (TC_TICK_ENDED()) [[unlikely]] {
            TC_RETURN(execute_status::success);
        }
    }
#endif
    // The fetch may have established a new mapping or moved pc off the
    // fall-through path; re-establish the segment bound before dispatching
    TC_SEG_TIGHTEN();
    TC_SYNC();
    TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS);
}

#if TC_PAGE_SEGMENT
/// \brief Continuation for a chain whose countdown expired.
/// \details Distinguishes the true tick end (chain exit, as before) from a
/// mere segment end, which re-derives the bound from the current pc and
/// the true tick end and continues the chain in place through the
/// validated fetch path, so segment expiry never pays an outer-loop round
/// trip. The materialization identity holds for zero and negative
/// countdowns alike, so the arithmetic is exact even after WFI overshoot
/// or a crossing-tightened bound.
template <typename STATE_ACCESS>
TC_CALLCONV static execute_status tc_seg_next(const STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS) {
    TC_ENTER();
    const uint64_t tc_mcycle_now = TC_MCYCLE_GET();
    const int64_t tc_ticks_left = static_cast<int64_t>(tcc->mcycle_tick_end - tc_mcycle_now);
    if (tc_ticks_left <= 0) [[unlikely]] {
        TC_RETURN(execute_status::success);
    }
    const int64_t tc_seg = std::min(tc_ticks_left, std::max(int64_t{0}, tc_seg_allowance(pc)));
    tc_remaining = static_cast<uint64_t>(tc_seg);
    tcc->mcycle_seg_end = tc_mcycle_now + static_cast<uint64_t>(tc_seg);
    TC_SYNC();
    TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);
}
#endif

// The countdown expiry exit: with page segments it resegments in-chain
// (only tc_seg_next decides whether the tick truly ended); otherwise the
// chain returns to the outer loop
#if TC_PAGE_SEGMENT
#define TC_COUNTDOWN_EXPIRED()                                                                                         \
    do {                                                                                                               \
        TC_SYNC();                                                                                                     \
        TC_MUSTTAIL return tc_seg_next<STATE_ACCESS>(a, insn TC_HOT_ARGS);                                             \
    } while (0)
#else
#define TC_COUNTDOWN_EXPIRED() TC_RETURN(execute_status::success)
#endif

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
        [[maybe_unused]] const auto tc_pc_in = pc;                                                                 \
        if constexpr (TC_PRELOAD_ENABLED != 0 && (PRELOAD) != 0) {                                                     \
            tc_next = tc_predecode_next(a, pc, (LEN), TC_PREDECODE_SAFE(LEN), tcc);                   \
        }                                                                                                              \
        const execute_status status = (EXPR);                                                                          \
        if (status > execute_status::success) [[unlikely]] {                                                           \
            TC_FETCH_TAG_INVALIDATE();                                                                                 \
            if (status >= execute_status::success_and_serve_interrupts) [[unlikely]] {                                 \
                --tc_remaining;                                                                                        \
                TC_RETURN(status);                                                                                     \
            }                                                                                                          \
        }                                                                                                              \
        if (TC_TICK_ENDED()) [[unlikely]] {                                                                            \
            TC_COUNTDOWN_EXPIRED();                                                                                    \
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
        if constexpr (TC_JIT_SHELL != 0 && (PRELOAD) == 1) {                                                           \
            /* conditional branch taken backward: a loop back-edge profiling site */                                   \
            if (status == execute_status::success && pc < tc_pc_in) {                                                  \
                [[maybe_unused]] const void *tc_tfn = tc_hook_site(a, tcc, pc_to_virtual(a, pc), 2);                                        \
                if constexpr (TC_AOT != 0 || TC_JIT != 0) {                                                            \
                    if (tc_tfn != nullptr) {                                                                           \
                        TC_JIT_COVER_ENTER();                                                                          \
                        TC_SYNC();                                                                                     \
                        TC_MUSTTAIL return reinterpret_cast<tc_handler_ptr<STATE_ACCESS>>(                             \
                            const_cast<void *>(tc_tfn))(a, insn TC_HOT_ARGS);                                          \
                    }                                                                                                  \
                }                                                                                                      \
                TC_ONLINE_TRIP_RETURN();                                                                               \
            }                                                                                                          \
        }                                                                                                              \
        /* In-segment fall-through: surviving the tick test proves the next                                            \
           fetch stays within the validated page, no cache check needed */                                             \
        if constexpr (TC_PAGE_SEGMENT != 0 && TC_PRELOAD_ENABLED == 0 && (PRELOAD) != 0) {                             \
            if (status == execute_status::success && ((PRELOAD) == 2 || pc == tc_pc_in + (LEN))) [[likely]] {          \
                uint32_t tc_next_insn = 0;                                                                             \
                a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index,            \
                    &tc_next_insn);                                                                                    \
                TC_SYNC();                                                                                             \
                TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS); \
            }                                                                                                          \
        }                                                                                                              \
        if (fetch_cache_is_hit(pc, TC_FETCH_TAG)) [[likely]] {                                                     \
            uint32_t tc_next_insn = 0;                                                                                 \
            TC_SEG_TIGHTEN();                                                                                          \
            a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index,                \
                &tc_next_insn);                                                                                        \
            TC_SYNC();                                                                                                 \
            TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS);     \
        }                                                                                                              \
        TC_SYNC();                                                                                                     \
        TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);                                           \
    }
#include "interpret-tc-cases.inc"
#undef TC_CASE

#if TC_AOT
/// \brief One recorded instruction inside a trace body: the case expression
/// with the recorded word, the handler macro's status handling, and a guard
/// that execution reached the recorded successor.
/// \details Accounting is deferred to block granularity: the generator's
/// entry and back-edge guards prove the tick cannot end inside the block,
/// so the straight path carries no per-step countdown work at all, early
/// exits charge their static pending count K, and the generator charges the
/// straight path once per block. Steps that observe mcycle materialize it
/// through TC_TRACE_MCYCLE with the same static K. Steps that write mcycle
/// (PRIVILEGED) are excluded at selection time.
#define TC_TRACE_STEP(EXPR, NEXT, K)                                                                                   \
    do {                                                                                                               \
        const execute_status tc_st = (EXPR);                                                                           \
        if (tc_st > execute_status::success) [[unlikely]] {                                                            \
            TC_FETCH_TAG_INVALIDATE();                                                                                 \
            if (tc_st >= execute_status::success_and_serve_interrupts) [[unlikely]] {                                  \
                tc_remaining -= (K);                                                                                   \
                TC_RETURN(tc_st);                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
        if (pc != pc_to_fast(a, (NEXT))) [[unlikely]] {                                                                \
            tc_remaining -= (K);                                                                                       \
            TC_TRACE_EXIT();                                                                                           \
        }                                                                                                              \
    } while (0)

/// \brief The architectural mcycle at pending step K of the current block.
#define TC_TRACE_MCYCLE(K) (TC_MCYCLE_GET() + (K) - 1)

/// \brief Leaves a trace at the current pc through the interpreter's fetch tail.
#define TC_TRACE_EXIT()                                                                                                \
    do {                                                                                                               \
        if (fetch_cache_is_hit(pc, TC_FETCH_TAG)) [[likely]] {                                                     \
            uint32_t tc_next_insn = 0;                                                                                 \
            a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index,                \
                &tc_next_insn);                                                                                        \
            TC_SYNC();                                                                                                 \
            TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS);     \
        }                                                                                                              \
        TC_SYNC();                                                                                                     \
        TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);                                           \
    } while (0)

/// \brief Entry guard failure: run the head instruction in the interpreter instead.
#define TC_TRACE_BAIL() TC_TRACE_EXIT()

#include TC_AOT_TRACES

/// \brief Head table generated with the traces.
template <typename STATE_ACCESS>
struct tc_trace_head {
    uint64_t pc;
    tc_handler_ptr<STATE_ACCESS> fn;
};

template <typename STATE_ACCESS>
static const tc_trace_head<STATE_ACCESS> tc_trace_heads[] = {
#define X(PC, FN) {PC, FN<STATE_ACCESS>},
    TC_TRACE_HEADS(X)
#undef X
};
#endif // TC_AOT

#if TC_JIT
/// \brief Where every exit from a compiled trace lands.
/// \details It is the interpreter's fetch tail and nothing else. Entering and
/// leaving a trace moves no state, because the stencils were compiled against
/// this same contract: the registers already hold pc, the countdown and the
/// fetch tag, so an exit is a jump. That is the property the whole design is
/// for, and the reason section 8b rejected a standard-ABI backend, whose every
/// entry and exit would have re-marshalled the interpreter's state instead.
///
/// The cycles a trace owed have already been charged by the stencil that
/// jumped here, so this only resumes interpretation at the current pc.
template <typename STATE_ACCESS>
TC_CALLCONV static execute_status tc_jit_side_exit(const STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS) {
    TC_ENTER();
    // The cycles the block owed were charged by the stencil that came here, and
    // charging them can be what ends the tick. Every handler tests the countdown
    // after retiring an instruction and before dispatching the next one; a trace
    // tests it once for a whole block instead, which leaves this test as the one
    // the block's own accounting still owes. Without it a trace whose last step
    // exhausts the countdown would dispatch one instruction past the boundary.
    TC_JIT_COVER_EXIT();
    if (static_cast<int64_t>(tc_remaining) <= 0) [[unlikely]] {
        TC_RETURN(execute_status::success);
    }
    if (fetch_cache_is_hit(pc, TC_FETCH_TAG)) [[likely]] {
        uint32_t tc_next_insn = 0;
        a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index, &tc_next_insn);
        TC_SYNC();
        TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(tc_next_insn)](a, tc_next_insn TC_HOT_ARGS);
    }
    TC_SYNC();
    TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);
}

/// \brief Turns a finished recording into machine code.
/// \details The shape is the AOT trace bodies of section 8b, built at run time
/// rather than emitted as C++: an entry guard that proves the whole block fits
/// inside the countdown, then one stencil per recorded instruction carrying no
/// accounting at all, then the block's cycles charged once. A cyclic recording
/// gets two blocks, the prologue it runs once and the body it repeats, and a
/// back edge that re-proves both of the loop's own conditions before repeating.
///
/// Steps are laid out in execution order so that each one's continuation is the
/// next byte and its jump can be dropped. What remains of a straight-line
/// instruction is its own work.
/// \returns The trace's entry point, or nullptr if it could not be built.
static const void *tc_jit_compile(tc_context<state_access> *c, const tc_online_state::trace &t) {
    tc_jit_cache *jc = &tc_jit_storage;
    if (!tc_jit_open(jc)) {
        return nullptr;
    }

    // How much of the recording the compiled set covers. A trace stops at the
    // first instruction that stays with the interpreter rather than skipping
    // it, because the steps after it are only reachable through it.
    uint32_t len = 0;
    while (len < t.len && tc_stencil_of_id[insn_get_id(t.entries[len].insn)] >= 0) {
        ++len;
    }
    if (len < tc_online_state::min_len) {
        ++jc->rejected;
        return nullptr;
    }
    if (len < t.len) {
        ++jc->truncated;
    }
    // A cycle whose body was cut off is no longer a cycle, and one whose last
    // step carries no successor guard cannot be closed at all: the back edge
    // takes it on trust that execution arrived back at the loop head.
    const bool cyclic = t.cycle >= 0 && static_cast<uint32_t>(t.cycle) < len && len == t.len &&
        tc_jit_is_guarded(static_cast<uint16_t>(tc_stencil_of_id[insn_get_id(t.entries[len - 1].insn)]));
    const uint32_t loop_at = cyclic ? static_cast<uint32_t>(t.cycle) : len;

    tc_jit_protect(jc, false);
    if (jc->failed) {
        return nullptr;
    }
    // Write and execute are never both granted, so while this function builds a
    // trace the cache holds no executable code at all -- including the traces
    // already in it. Restoring that has to happen on every way out, not just
    // the one that succeeds: a build that gives up partway would otherwise
    // leave every installed trace unexecutable, and the next entry into one
    // would fault on its first instruction.
    const auto reprotect = scope_exit([jc] { tc_jit_protect(jc, true); });
    const size_t start = jc->used;
    const void *const exit = reinterpret_cast<const void *>(&tc_jit_side_exit<state_access>);
    // Nothing that follows knows its successor's address yet, so every stencil
    // is emitted with its continuation elided and simply falls through; the only
    // jump that has to name an address is the loop's back edge, and it is
    // emitted last, when the address it names is known.
    tc_jit_operands op{};
    op.exit = exit;
    op.cont = nullptr;

    // Entry guard: the first block covers the prologue and one pass of the body
    op.insn = 0;
    op.k = len;
    if (tc_jit_emit(jc, TC_STENCIL_INDEX_GUARD, op, true) == 0) {
        jc->used = start;
        return nullptr;
    }
    const uint8_t *const entry = jc->base + start;

    size_t loop_head = 0;
    for (uint32_t i = 0; i < len; ++i) {
        if (i == loop_at) {
            // The prologue ran; charge it before the body starts repeating, so
            // that the body's own constants hold on every iteration
            if (loop_at > 0) {
                op.insn = 0;
                op.k = loop_at;
                if (tc_jit_emit(jc, TC_STENCIL_INDEX_CHARGE, op, true) == 0) {
                    jc->used = start;
                    return nullptr;
                }
            }
            loop_head = jc->used;
        }
        const tc_online_entry &e = t.entries[i];
        op.insn = e.insn;
        op.next_delta = static_cast<int64_t>(e.next_pc) - static_cast<int64_t>(e.vaddr);
        // Cycles this block owes once this step has run, counted from the block
        // it belongs to; an exit here charges exactly what has retired
        op.k = (i < loop_at ? i : i - loop_at) + 1;
        const int16_t s = tc_stencil_of_id[insn_get_id(e.insn)];
        if (tc_jit_emit(jc, static_cast<uint16_t>(s), op, true) == 0) {
            jc->used = start;
            return nullptr;
        }
    }

    op.insn = 0;
    if (cyclic) {
        // Back edge: charge the iteration, then require both that execution
        // arrived back at the recorded loop head and that another pass fits
        op.k = len - loop_at;
        op.cont = jc->base + loop_head;
        if (tc_jit_emit(jc, TC_STENCIL_INDEX_LOOP, op, false) == 0) {
            jc->used = start;
            return nullptr;
        }
    } else {
        // Straight recording: one block, charge it and leave
        op.k = len;
        op.cont = exit;
        if (tc_jit_emit(jc, TC_STENCIL_INDEX_CHARGE, op, false) == 0) {
            jc->used = start;
            return nullptr;
        }
    }

    // Debug aid: stop in the debugger right after compiling the trace whose
    // head is named in TC_JIT_BREAK, so a session can step the emitted code of a
    // chosen trace without guessing at addresses or compile ordinals.
    if (const char *want = std::getenv("TC_JIT_BREAK"); want != nullptr) {
        if (t.head == std::strtoull(want, nullptr, 16)) {
            std::fprintf(stderr, "tc-jit: BREAK head %llx entry %p len %u cyclic %d\n",
                static_cast<unsigned long long>(t.head), static_cast<const void *>(entry), len,
                static_cast<int>(cyclic));
            raise(SIGTRAP);
        }
    }
    if (std::getenv("TC_JIT_DEBUG") != nullptr && jc->compiled < 100000) {
        std::fprintf(stderr, "tc-jit: trace head %llx len %u/%u cyclic %d loop_at %u at %p exit %p\n",
            static_cast<unsigned long long>(t.head), len, t.len, static_cast<int>(cyclic), loop_at,
            static_cast<const void *>(entry), exit);
        for (size_t i = 0; i < jc->used - start; ++i) {
            std::fprintf(stderr, "%02x", entry[i]);
        }
        std::fprintf(stderr, "\n");
    }
    if (jc->failed) {
        jc->used = start;
        return nullptr;
    }
    ++jc->compiled;
    jc->cyclic += cyclic ? 1 : 0;
    jc->steps += len;
    jc->bytes += jc->used - start;
    (void) c;
    return entry;
}

/// \brief Prints backend statistics at exit when TC_JIT_STATS is set.
__attribute__((destructor)) static void tc_jit_report() {
    if (std::getenv("TC_JIT_STATS") == nullptr) {
        return;
    }
    const auto &j = tc_jit_storage;
    std::fprintf(stderr,
        "tc-jit: compiled %llu (cyclic %llu, %llu steps, %llu bytes) rejected %llu truncated %llu unreachable %llu\n"
        "tc-jit: entered %llu stale %llu flushes %llu loops %llu insns-in-trace %llu\n",
        static_cast<unsigned long long>(j.compiled), static_cast<unsigned long long>(j.cyclic),
        static_cast<unsigned long long>(j.steps), static_cast<unsigned long long>(j.bytes),
        static_cast<unsigned long long>(j.rejected), static_cast<unsigned long long>(j.truncated),
        static_cast<unsigned long long>(j.out_of_reach), static_cast<unsigned long long>(j.entered),
        static_cast<unsigned long long>(j.stale), static_cast<unsigned long long>(j.flushes),
        static_cast<unsigned long long>(j.loops), static_cast<unsigned long long>(j.insns));
#if TC_JIT_COVERAGE
    for (uint32_t k = 0; k < TC_HEAD_SLOTS; ++k) {
        if (j.per_head[k] > (j.entered / 40)) {
            std::fprintf(stderr, "tc-jit: hot head %llx entries %llu\n",
                static_cast<unsigned long long>(j.per_head_pc[k]), static_cast<unsigned long long>(j.per_head[k]));
        }
    }
#endif
}
#endif // TC_JIT

#undef TC_RETURN

/// \brief Tail-call variant of the interpreter hot loop; same observable behavior as interpret_loop().
template <typename STATE_ACCESS>
static NO_INLINE execute_status interpret_loop_tc_body(const STATE_ACCESS a, uint64_t mcycle_end, uint64_t mcycle) {
    // pc travels as a fast address encoding vpc + K (the deposited fetch
    // mapping offset); at entry there is no mapping, so K = 0 encodes the
    // architectural pc directly and the invalidated fetch cache routes the
    // first fetch through the translating miss path
    a.write_fetch_vf_offset(i_state_access_fast_addr_t<STATE_ACCESS>{});
    auto pc = pc_to_fast(a, a.read_pc());
    if ((pc & 1) != 0) {
        pc = raise_exception(a, pc, MCAUSE_INSN_ADDRESS_MISALIGNED, pc_to_virtual(a, pc));
    }

    auto *const tcc = new (a.get_penumbra().scratch) tc_context<STATE_ACCESS>{};
    tcc->mcycle_end = mcycle_end;
    tcc->fetch_vaddr_page = ensure_fetch_cache_miss(pc);
    tcc->fetch_pma_index = TLB_INVALID_PMA_INDEX;
#if TC_JIT_SHELL
    for (auto &c : tcc->hot.hotcount) {
        c = TC_HOT_RESET;
    }
    for (auto &p : tcc->hot.head_pc) {
        p = UINT64_MAX;
    }
    tcc->hot.entries = 0;
#endif
#if TC_AOT
    // Install the generated traces, hottest first, first claim per slot
    for (const auto &head : tc_trace_heads<STATE_ACCESS>) {
        const uint32_t h = (static_cast<uint32_t>(head.pc) >> 1) & (TC_HEAD_SLOTS - 1);
        if (tcc->hot.head_pc[h] == UINT64_MAX) {
            tcc->hot.head_pc[h] = head.pc;
            tcc->hot.head_fn[h] = reinterpret_cast<const void *>(head.fn);
        }
    }
#endif
#if TC_JIT
    ++tc_jit_storage.loops;
#endif
#if TC_ONLINE
    tcc->online = &tc_online_storage;
    // Re-register heads installed by earlier interpret() calls
    for (uint32_t i = 0; i < tc_online_storage.ntraces; ++i) {
        const auto &t = tc_online_storage.pool[i];
        const uint32_t h = (static_cast<uint32_t>(t.head) >> 1) & (TC_HEAD_SLOTS - 1);
        tcc->hot.head_pc[h] = t.head;
#if TC_JIT
        // Restore what the head resolves to as well. Restoring only the pc
        // leaves a head that matches and dispatches nowhere, and since the head
        // still counts as installed it will not be recorded again either.
        tcc->hot.head_fn[h] = t.entry;
        tcc->hot.head_key[h] = t.key;
#endif
    }
#endif

    while (mcycle < mcycle_end) {
        if (rtc_is_tick(mcycle)) {
            set_rtc_interrupt(a, mcycle);
            if constexpr (is_an_i_interactive_state_access_v<STATE_ACCESS>) {
                a.poll_external_interrupts(mcycle, mcycle);
            }
        }

        pc = raise_interrupt_if_any(a, pc, tcc->fetch_vaddr_page);

#ifndef NDEBUG
        assert_no_brk(a);
#endif

        const uint64_t mcycle_tick_end = mcycle + std::min(mcycle_end - mcycle, RTC_FREQ_DIV - (mcycle % RTC_FREQ_DIV));
        tcc->mcycle_tick_end = mcycle_tick_end;

        execute_status status = execute_status::success;
        while (mcycle < mcycle_tick_end) {
            uint32_t insn = 0;
            if (fetch_insn(a, pc, insn, tcc->fetch_vaddr_page, tcc->fetch_pma_index) == fetch_status::success)
                [[likely]] {
#if TC_ONLINE
                if (tcc->online_trip) [[unlikely]] {
                    tcc->online_trip = false;
                    tc_online_debug("trip", tcc->online_trip_pc, tcc->online_trip_weight);
                    tc_online_begin(tcc, tcc->online_trip_pc);
                }
                if (tcc->online->recording) [[unlikely]] {
                    // Recordings are keyed by the architectural pc: fast
                    // encodings are not stable across mappings or runs
#if TC_JIT
                    // Which host page this instruction came from. Recorded
                    // here, where the fetch just happened and pc is therefore
                    // the host address of the instruction itself, so an
                    // installed trace names the memory it was read out of.
                    tcc->jit_key = static_cast<uint64_t>(pc) & ~PAGE_OFFSET_MASK;
#endif
                    tc_online_record(tcc, pc_to_virtual(a, pc), insn);
                }
#endif
#if TC_PAGE_SEGMENT
                // Bound the chain by the fall-through fetches that provably
                // stay within pc's page, in addition to the tick
                const uint64_t tc_avail = std::min(mcycle_tick_end - mcycle,
                    static_cast<uint64_t>(std::max(int64_t{0}, tc_seg_allowance(pc))));
#else
                const uint64_t tc_avail = mcycle_tick_end - mcycle;
#endif
#if TC_ONLINE
                const bool tc_is_recording = tcc->online->recording;
                // One-instruction chains while recording; the adjusted tick
                // base keeps the mcycle materialization identity exact.
                const uint64_t tc_chain_remaining = tc_is_recording ? 1 : tc_avail;
                const uint64_t tc_chain_tick_end = tc_is_recording ? mcycle + 1 : mcycle + tc_avail;
#else
                const uint64_t tc_chain_remaining = tc_avail;
                const uint64_t tc_chain_tick_end = mcycle + tc_avail;
#endif
#if TC_PAGE_SEGMENT
                tcc->mcycle_seg_end = tc_chain_tick_end;
#else
                tcc->mcycle_tick_end = tc_chain_tick_end;
#endif
#if TC_GLOBAL_REGS
                cartesi::tc_reg_pc = static_cast<uint64_t>(pc);
                // Write the pinned countdown only once, after the conditional.
                // Multiple writes around the branch make Clang 22 incorrectly
                // hoist the recording value (1) onto the non-recording path.
                cartesi::tc_remaining = tc_chain_remaining;
                cartesi::tcc = tcc;
                cartesi::tc_reg_fetch_page = static_cast<uint64_t>(tcc->fetch_vaddr_page);
                status = tc_jumptable<STATE_ACCESS>[insn_get_id(insn)](a, insn);
#elif TC_PAGE_SEGMENT
                status = tc_jumptable<STATE_ACCESS>[insn_get_id(insn)](a, insn, pc, tc_chain_remaining);
#else
                status = tc_jumptable<STATE_ACCESS>[insn_get_id(insn)](a, insn, pc, tc_chain_remaining,
                    tcc->fetch_vaddr_page);
#endif
                pc = tcc->pc;
                mcycle = tcc->mcycle;
                break;
            }
            // Fetch raised an exception: it consumes one cycle and execution continues
            // from the exception handler pc
            ++mcycle;
        }

        if (status >= execute_status::success_and_yield) [[unlikely]] {
            // Got an interruption that must be handled externally
            a.write_pc(pc_to_virtual(a, pc));
            a.write_mcycle(mcycle);
            return status;
        }
        // Else status is success (tick or mcycle_end reached) or
        // success_and_serve_interrupts (outer loop serves interrupts): continue
    }

    // Commit machine state
    a.write_pc(pc_to_virtual(a, pc));
    a.write_mcycle(mcycle);
    return execute_status::success;
}

#if TC_GLOBAL_REGS
/// \brief Snapshot of the four reserved registers' values.
struct tc_saved_regs {
    uint64_t r[4];
};

/// \brief Reads the reserved registers through asm the compiler cannot analyze.
/// \details Plain reads and writes of the register globals are not enough:
/// Clang assumes -ffixed registers cannot change across calls and deletes a
/// same-value save/restore pair around the interpreter run, which corrupts
/// the caller's callee-saved registers.
static FORCE_INLINE tc_saved_regs tc_save_pinned_regs() {
    tc_saved_regs s;
#if defined(__aarch64__)
    asm volatile("mov %0, x23\n\tmov %1, x24\n\tmov %2, x25\n\tmov %3, x27"
        : "=r"(s.r[0]), "=r"(s.r[1]), "=r"(s.r[2]), "=r"(s.r[3])
        :
        : "memory");
#else
    asm volatile("mov %%rbx, %0\n\tmov %%r12, %1\n\tmov %%r13, %2\n\tmov %%r15, %3"
        : "=r"(s.r[0]), "=r"(s.r[1]), "=r"(s.r[2]), "=r"(s.r[3])
        :
        : "memory");
#endif
    return s;
}

/// \brief Writes the reserved registers through asm the compiler cannot analyze.
static FORCE_INLINE void tc_restore_pinned_regs(const tc_saved_regs &s) {
#if defined(__aarch64__)
    asm volatile("mov x23, %0\n\tmov x24, %1\n\tmov x25, %2\n\tmov x27, %3"
        :
        : "r"(s.r[0]), "r"(s.r[1]), "r"(s.r[2]), "r"(s.r[3])
        : "memory");
#else
    asm volatile("mov %0, %%rbx\n\tmov %1, %%r12\n\tmov %2, %%r13\n\tmov %3, %%r15"
        :
        : "r"(s.r[0]), "r"(s.r[1]), "r"(s.r[2]), "r"(s.r[3])
        : "memory");
#endif
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
