// Copy-and-patch backend state (copy-patch-rvvm.md, plan
// streamed-floating-ember). Data-structure provenance is documented in the
// plan: the front cache and code heap are RVVM ports, the head map and
// traced-page set are the kept interpret-tc mechanisms, the per-trace
// metadata exists only for kept invariants (mapping validation, cycle
// exactness, eager invalidation), and formation state follows RVVM's
// rvjit_block_t with a guest-indexed register cache.

#ifndef CP_CONTEXT_HPP
#define CP_CONTEXT_HPP

#include <cstdint>

#include "cp-emit.h"
#include "cp-stencils-tables.h"

namespace cartesi {

struct cp_trace {
    static constexpr uint32_t max_hpages = 4;
    uint64_t head;           ///< Guest virtual pc of the entry
    uint64_t code_vf_offset; ///< Mapping-validation value latched at formation
    uint8_t *code_start;
    uint32_t code_size;
    uint32_t len; ///< Guest instructions, the worst-case pending charge
    uint64_t hpage[max_hpages];
    uint8_t nhpages;
    bool dead;
    const void *fn; ///< Entry pointer (the tick guard)
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
    uint32_t guard_site;  ///< Offset of the guard's bail branch in the trace
    uint8_t guard_kind;   ///< CP_P_JUMP26 or CP_P_JMPREL32
    int32_t guard_addend; ///< Patch addend of that site
    int64_t delta;        ///< Signed fast-pc displacement head -> off path
    uint32_t pending;     ///< Instructions retired when the bail is taken
    uint32_t dirty;       ///< Dirty-slot snapshot at the guard
};

struct cp_state {
    static constexpr uint32_t max_traces = 16384;
    static constexpr uint32_t set_slots = 65536; ///< 4x traces, power of two
    static constexpr uint32_t front_size = 256;  ///< RVVM_TLB_SIZE
    static constexpr uint16_t interpreted_marker = 0xffff;
    static constexpr uint32_t nslots = 7; ///< Guest cache slots in the contract
    static constexpr uint32_t max_bails = 64;

    cp_heap_t heap;
    const void *continue_island; ///< far-jump to the interpreter continuation

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

    static constexpr uint32_t max_len = 256; ///< Guest instructions per trace
    uint64_t heap_reset_curr; ///< Heap cursor after the island, flush target

    // Formation: the one open trace.
    bool recording;
    bool rec_failed;         ///< Emission overflow or slot exhaustion mid-insn
    uint64_t rec_head;       ///< Guest vaddr of the head
    uint64_t rec_vaddr;      ///< Guest vaddr of the instruction being recorded
    uint64_t rec_end_vaddr;  ///< Guest vaddr execution continues at
    uint64_t rec_code_vf_offset;
    uint64_t rec_ctx_slot_base;
    uint64_t rec_alloc_start; ///< Heap cursor at begin, the rollback target
    uint8_t *rec_start;      ///< Entry (tick guard) address
    uint8_t *rec_insn_start; ///< Rollback cursor for the current instruction
    uint32_t rec_len;
    uint8_t *rec_tick_site;  ///< Tick guard address, pending hole re-patched
                             ///< at finish
    uint64_t rec_hpage[cp_trace::max_hpages];
    uint8_t rec_nhpages;
    uint64_t begin_ns;
    // Register cache, guest-indexed (RVVM regs[32] shape): slot or -1,
    // dirty and loaded bits; slot_guest is the reverse map for stores.
    int8_t reg_slot[32];
    uint32_t reg_dirty;  ///< Bit per slot
    uint8_t slot_guest[nslots];
    uint8_t nslots_used;
    // Pending branch: direction known only when the next instruction's pc
    // arrives, so branches lag one record call.
    bool have_pending_branch;
    uint64_t pb_vaddr;
    uint64_t pb_taken_target;
    const cp_stencil_t *const (*pb_tab)[7];  ///< Guard when recorded taken
    const cp_stencil_t *const (*pb_comp)[7]; ///< Guard when recorded not taken
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
};

} // namespace cartesi

#endif
