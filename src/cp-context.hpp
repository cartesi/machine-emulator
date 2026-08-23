// Copy-and-patch backend state (copy-patch-rvvm.md, plan
// streamed-floating-ember). Data-structure provenance is documented in the
// plan: the front cache and code heap are RVVM ports, the head map and
// traced-page set are the kept interpret-tc mechanisms, the per-trace
// metadata exists only for kept invariants (mapping validation, cycle
// exactness, eager invalidation), and formation state follows RVVM's
// rvjit_block_t with a guest-indexed register cache.

#ifndef CP_CONTEXT_HPP
#define CP_CONTEXT_HPP

/// \brief Guest cache slot count, a per-arch build parameter (the aarch64
/// preserve_none layout carries up to 12 slot positions; measured hot-loop
/// demand is 8-10).
#ifndef CP_NSLOTS
#define CP_NSLOTS 7
#endif

#include <cstdint>

#include "cp-emit.h"
#include "cp-stencils-tables.h"

namespace cartesi {

struct cp_trace {
    static constexpr uint32_t max_hpages = 4;
    uint64_t head;           ///< Guest virtual pc of the entry
    uint64_t code_vf_offset; ///< Mapping-validation value latched at formation
    uint64_t ctx_slot_base;  ///< Translation-context partition at formation:
                             ///< entering under another context would skip
                             ///< the code-TLB fills the interpreter performs,
                             ///< and the shadow TLB is hashed state
    uint8_t *code_start;
    uint32_t code_size;
    uint32_t len; ///< Guest instructions, the worst-case pending charge
    uint64_t hpage[max_hpages];
    uint8_t nhpages;
    bool dead;
    bool carried;        ///< Loop-carried cyclic form (diagnostics)
    uint32_t exec_count; ///< Hook entries into this trace (C-side, diagnostics)
    const void *fn;      ///< Entry pointer (the tick guard)
    const void *call_fn; ///< Call-entry prologue: mapping establishment, then fn
    // Straight-exit link (RVVM block_links analog, one trailing site per
    // trace): the terminal exit's branch, retargeted from the island to the
    // successor's entry when both ends are installed in the same guest page.
    uint64_t successor;   ///< Guest vaddr the straight exit leaves for
    uint32_t link_site;   ///< Heap offset of the trailing branch, 0 if none
    int32_t link_addend;  ///< Patch addend of that site
    uint8_t link_kind;    ///< CP_P_JUMP26 or CP_P_JMPREL32
    uint16_t link_target; ///< Pool index of the linked successor, none_link if unlinked
};

/// \brief RVVM jtlb port: direct-mapped pc-to-entry cache probed by the
/// lookup-tail stencil (increment 4).
struct cp_front_entry {
    uint64_t pc;
    const void *fn;
};

/// \brief A deferred guard bail: guards elide their continue side, so bail
/// blocks are emitted grouped after the terminal (the side-exit island
/// shape) and each guard's bail branch is patched to its block.
struct cp_bail {
    uint32_t guard_site;           ///< Offset of the guard's bail branch in the trace
    uint8_t guard_kind;            ///< CP_P_JUMP26 or CP_P_JMPREL32
    int32_t guard_addend;          ///< Patch addend of that site
    int64_t delta;                 ///< Signed fast-pc displacement head -> off path
    uint32_t pending;              ///< Instructions retired when the bail is taken
    uint32_t dirty;                ///< Dirty-slot snapshot at the guard
    uint8_t slot_guest[CP_NSLOTS]; ///< Slot-to-guest mapping at the guard: eviction
                                   ///< remaps slots mid-trace, so the bail stores
                                   ///< must use the mapping the guard saw
    bool is_branch;                ///< Branch-direction guard (else memory guard)
    bool is_fp;                    ///< FP hard-guard miss: run soft_only and rejoin
    bool is_cold;                  ///< Guard failure must leave for portable execution
    uint32_t fp_insn;              ///< Constant instruction word for the soft body
    uint32_t fp_resume;            ///< Heap offset after the hard-result store
};

struct cp_state {
    static constexpr uint32_t max_traces = 16384;
    static constexpr uint32_t set_slots = 65536; ///< 4x traces, power of two
    static constexpr uint32_t front_size = 256;  ///< RVVM_TLB_SIZE
    static constexpr uint16_t interpreted_marker = 0xffff;
    static constexpr uint32_t nslots = CP_NSLOTS; ///< Guest cache slots in the contract
    static constexpr uint32_t max_bails = 64;
    static constexpr uint16_t none_link = 0xffff;

    cp_heap_t heap;
    const void *continue_island;      ///< far-jump to cp_continue (enter or trip on exit)
    const void *continue_cold_island; ///< far-jump to cp_continue_cold (resume only)
    // Per-cause counting islands: each cold bail path routes through a
    // counter bump before the far jump, so the statistics attribute every
    // unproductive entry to its guard.
    const void *tick_island;
    const void *ctx_island;
    const void *page_island;
    const void *vh_island;
    const void *miss_island;
    const void *branch_bail_island;
    const void *mem_bail_island;
    const void *mem_bail_cold_island; ///< Zero-retirement bails: re-entering
                                      ///< would loop without progress, only
                                      ///< the interpreter slow path advances
    const void *terminal_island;

    cp_front_entry front[front_size];

    cp_trace pool[max_traces];
    uint32_t ntraces;

    // Exact head map (kept interpret-tc shape): tag pc+1, value index+1 or
    // the interpreted marker; dead-aware find, no eviction, flush-all only.
    uint64_t installed_pc[set_slots];
    uint16_t installed_trace[set_slots];

    // Traced host pages feeding the write-hook kill scan.
    uint64_t traced_page[set_slots];
    uint32_t ntraced_pages;

    // Pending-link table (RVVM heap.block_links analog, allocation-free):
    // open-addressed by successor pc, chaining waiting predecessors through
    // link_next. Consumed when the successor installs; cleared by flush.
    uint64_t pending_link_pc[set_slots];
    uint16_t pending_link_trace[set_slots];
    uint16_t link_next[max_traces];

    static constexpr uint32_t max_len = 256;  ///< Guest instructions per trace
    static constexpr uint32_t max_log = 4096; ///< Emission-log records
    uint64_t heap_reset_curr;                 ///< Heap cursor after the island, flush target

    /// rief One logged body emission, enough to replay it: the loop-carry
    /// transform re-emits an eligible cyclic body with first-use loads
    /// hoisted to a preheader, so nothing positional survives a reorder.
    struct cp_emit_rec {
        const cp_stencil_t *st;
        uint64_t imm0;
        uint64_t imm1;
        int16_t bail_index;        ///< bails[] entry to re-site at replay, -1 none
        int16_t resume_bail_index; ///< FP bail whose success resumes after this emission
        int8_t load_slot;          ///< Hoistable first-use load target, -1 none
    };
    cp_emit_rec rec_log[max_log]; ///< Formation scratch, one open recording
    uint32_t rec_log_len;
    uint32_t snap_log_len;      ///< Rolled back with the per-insn snapshot
    bool rec_carry_ok;          ///< Loop-carry eligibility: guest and scratch
                                ///< slot sets stay disjoint (a preheader-loaded
                                ///< value must survive the whole body, and an
                                ///< eviction spill would republish stale slots
                                ///< on later iterations), and the log fit
    uint32_t rec_guest_slots;   ///< Slots ever bound to a guest register
    uint32_t rec_scratch_slots; ///< Slots ever taken as scratch
    uint32_t snap_guest_slots;
    uint32_t snap_scratch_slots;
    bool snap_carry_ok;

    // Formation: the one open trace.
    bool recording;
    bool rec_failed;        ///< Emission overflow or slot exhaustion mid-insn
    uint64_t rec_head;      ///< Guest vaddr of the head
    uint64_t rec_vaddr;     ///< Guest vaddr of the instruction being recorded
    uint64_t rec_end_vaddr; ///< Guest vaddr execution continues at
    uint64_t rec_code_vf_offset;
    uint64_t rec_ctx_slot_base;
    uint64_t rec_alloc_start; ///< Heap cursor at begin, the rollback target
    uint8_t *rec_start;       ///< Entry address (tick guard, or the carried preheader)
    uint8_t *rec_body_start;  ///< First byte after the call prologue, the
                              ///< replay rollback point
    uint8_t *rec_call_start;  ///< Call-entry prologue address
    uint8_t *rec_insn_start;  ///< Rollback cursor for the current instruction
    uint32_t rec_len;
    uint8_t *rec_tick_site; ///< Tick guard address, pending hole re-patched
                            ///< at finish
    uint64_t rec_hpage[cp_trace::max_hpages];
    uint8_t rec_nhpages;
    uint64_t begin_ns;
    // Register cache, guest-indexed (RVVM regs[32] shape): slot or -1,
    // dirty and loaded bits; slot_guest is the reverse map for stores.
    int8_t reg_slot[32];
    uint32_t reg_dirty; ///< Bit per slot
    uint8_t slot_guest[nslots];
    uint8_t nslots_used;
    // Eviction state (RVVM regs[].last_used): once all slots fill, the
    // least-recently-used unlocked slot spills (store if dirty) and remaps.
    uint32_t rec_last_used[nslots];
    uint32_t rec_use_clock;
    // Register-cache snapshot taken with rec_insn_start: the uncompilable
    // rollback discards the failed instruction's emitted bytes, including
    // any eviction spills, so the bookkeeping those allocations mutated
    // must be restored with the heap cursor or spilled registers are lost.
    int8_t snap_reg_slot[32];
    uint8_t snap_slot_guest[nslots];
    uint32_t snap_reg_dirty;
    uint8_t snap_nslots_used;
    uint32_t snap_last_used[nslots];
    uint32_t snap_use_clock;
    // Pending branch: direction known only when the next instruction's pc
    // arrives, so branches lag one record call.
    bool have_pending_branch;
    uint64_t pb_vaddr;
    uint64_t pb_taken_target;
    const cp_stencil_t *const (*pb_tab)[CP_NSLOTS];  ///< Guard when recorded taken
    const cp_stencil_t *const (*pb_comp)[CP_NSLOTS]; ///< Guard when recorded not taken
    uint8_t pb_rs1;
    uint8_t pb_rs2;
    uint8_t pb_size;
    // Deferred guard bails for this trace.
    cp_bail bails[max_bails];
    uint32_t nbails;

    // Statistics (reported per the doc's requirement).
    uint64_t installed;
    uint64_t empty_marked;
    uint64_t flushes;
    uint64_t invalidated;
    uint64_t emitted_bytes;
    uint64_t compile_ns;
    uint64_t entries;
    uint64_t call_entries;
    uint64_t links;
    uint64_t links_severed;
    uint64_t tick_bails;     ///< Entries rejected by the tick guard
    uint64_t ctx_bails;      ///< Call entries rejected by the context guard
    uint64_t page_bails;     ///< Call entries rejected by the hot-slot page probe
    uint64_t vh_bails;       ///< Call entries rejected by the hot-slot vh probe
    uint64_t lookup_misses;  ///< Dynamic terminals whose front probe missed
    uint64_t branch_bails;   ///< Exits through a branch-direction guard
    uint64_t mem_bails;      ///< Exits through a memory (hot-TLB) guard
    uint64_t fp_soft_calls;  ///< Hard FP guard misses completed by soft_only
    uint64_t terminal_exits; ///< Straight-terminal exits (cyclic tick bails count as tick)
    // Formation-cause counters: what ended each recording.
    uint64_t fin_cyclic;
    uint64_t fin_dynamic;   ///< JALR-class terminal
    uint64_t fin_page;      ///< Guest-page crossing or mapping change
    uint64_t fin_installed; ///< Stopped at an installed head
    uint64_t fin_maxlen;
    uint64_t fin_uncompilable; ///< Unclassifiable instruction rollback
    uint64_t fin_trap;         ///< Successor mismatch (trap between records)
    uint64_t evictions;        ///< Register-cache spills during formation
    uint64_t continue_enters;  ///< Exits that entered an installed trace from C
    uint64_t continue_trips;   ///< Exits that tripped compilation (dispatcher miss)
    uint64_t carried;          ///< Cyclic traces installed in loop-carried form
};

} // namespace cartesi

#endif
