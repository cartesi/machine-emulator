// Copy-and-patch backend engine (copy-patch-rvvm.md, plan
// streamed-floating-ember). Included by interpret-tc.cpp under
// TC_COPY_PATCH, next to where the lightning backend lives, so it shares
// the interpreter's types and helpers. Policy is RVVM's: compile on first
// miss, keep everything, flush-all when full, guard failures bail with
// nothing recorded. Mechanisms are the kept interpret-tc ones: exact head
// map, code_vf_offset validation, write-hook invalidation, outer-loop
// recording with one-instruction chains, fetch-tail exits.

// Label enum and per-label size, re-expanded from the same generated
// sources the dispatch uses, so classification is single-source.
enum class tc_label : uint16_t {
#define TC_CASE(LABEL, ...) LABEL,
#include "interpret-tc-cases.inc"
#undef TC_CASE
};

static constexpr uint8_t cp_label_size[] = {
#define TC_CASE(LABEL, CLASS, SIZE, ...) (SIZE),
#include "interpret-tc-cases.inc"
#undef TC_CASE
};

// 65536-entry classification, indexed by insn_get_id like the jump table.
static const tc_label cp_label_table[1 << 16] = {
#define TC_LABEL(LABEL) tc_label::LABEL
#include "interpret-tc-table.inc"
#undef TC_LABEL
};

static uint64_t cp_now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

// ---------------------------------------------------------------------------
// Head map and traced-page set (kept interpret-tc shapes).

// The stencil contract is purely positional over the preserve_none argument
// order (tools/cp-gen-stencils.lua). AArch64 keeps the pinned roster at its
// existing positions. On x86-64 the five live interpreter values lead the
// roster, making every in-chain trace transfer a plain tail branch; one
// outer entry call establishes the cache-slot and context stack positions.
#if defined(__x86_64__)
#if CP_NSLOTS == 6
template <typename STATE_ACCESS>
using cp_chain_fn = TC_CALLCONV execute_status(const STATE_ACCESS, uint32_t,
    i_state_access_fast_addr_t<STATE_ACCESS>, uint64_t, i_state_access_fast_addr_t<STATE_ACCESS>, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, tc_context<STATE_ACCESS> *);
#elif CP_NSLOTS == 7
template <typename STATE_ACCESS>
using cp_chain_fn = TC_CALLCONV execute_status(const STATE_ACCESS, uint32_t,
    i_state_access_fast_addr_t<STATE_ACCESS>, uint64_t, i_state_access_fast_addr_t<STATE_ACCESS>, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t, tc_context<STATE_ACCESS> *);
#else
#error "extend the x86-64 copy-and-patch chain entry roster for this CP_NSLOTS"
#endif

template <typename STATE_ACCESS>
static NO_INLINE execute_status cp_enter_chain(const STATE_ACCESS a, uint32_t insn,
    i_state_access_fast_addr_t<STATE_ACCESS> pc, uint64_t cd, i_state_access_fast_addr_t<STATE_ACCESS> fetch,
    tc_context<STATE_ACCESS> *tcc, const void *fn) {
    // The target may be a five-argument interpreter handler or a complete
    // stencil entry. Their leading physical arguments are identical; the
    // extra cache/context positions establish the frame used by traces.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
#if CP_NSLOTS == 6
    return reinterpret_cast<cp_chain_fn<STATE_ACCESS> *>(const_cast<void *>(fn))(a, insn, pc, cd, fetch, 0, 0, 0, 0,
        0, tcc);
#else
    return reinterpret_cast<cp_chain_fn<STATE_ACCESS> *>(const_cast<void *>(fn))(a, insn, pc, cd, fetch, 0, 0, 0, 0,
        0, 0, tcc);
#endif
}
#endif

static FORCE_INLINE uint32_t cp_pc_slot(uint64_t pc) {
    uint64_t key = pc ^ (pc >> 12);
    return (static_cast<uint32_t>(key) >> 1) & (cp_state::set_slots - 1);
}

static FORCE_INLINE const cp_trace *cp_find(const cp_state *c, uint64_t pc, bool *interpreted = nullptr) {
    uint32_t s = cp_pc_slot(pc);
    const uint64_t tag = pc + 1;
    while (c->installed_pc[s] != 0) {
        if (c->installed_pc[s] == tag) {
            const uint16_t idx = c->installed_trace[s];
            if (idx == cp_state::interpreted_marker) {
                if (interpreted != nullptr) {
                    *interpreted = true;
                }
                return nullptr;
            }
            const cp_trace *t = &c->pool[idx - 1];
            return t->dead ? nullptr : t;
        }
        s = (s + 1) & (cp_state::set_slots - 1);
    }
    return nullptr;
}

static void cp_insert(cp_state *c, uint64_t pc, uint16_t value) {
    uint32_t s = cp_pc_slot(pc);
    const uint64_t tag = pc + 1;
    while (c->installed_pc[s] != 0 && c->installed_pc[s] != tag) {
        s = (s + 1) & (cp_state::set_slots - 1);
    }
    c->installed_pc[s] = tag;
    c->installed_trace[s] = value;
}

static FORCE_INLINE uint32_t cp_hpage_slot(uint64_t hpage) {
    uint64_t key = hpage >> 12;
    key ^= key >> 12;
    return static_cast<uint32_t>(key) & (cp_state::set_slots - 1);
}

static void cp_insert_hpage(cp_state *c, uint64_t hpage) {
    uint32_t s = cp_hpage_slot(hpage);
    const uint64_t tag = hpage + 1;
    while (c->traced_page[s] != 0) {
        if (c->traced_page[s] == tag) {
            return;
        }
        s = (s + 1) & (cp_state::set_slots - 1);
    }
    c->traced_page[s] = tag;
    ++c->ntraced_pages;
}

// Front cache (RVVM jtlb): one direct-mapped bank per translation context.
// Generated lookup tails bake their recording context's bank address, so
// they cannot bypass the single trace's context tag. The exact head map
// remains single-trace-per-pc; these banks are only lookup accelerators.
static_assert(sizeof(cp_front_entry) == 16, "lookup stencil indexes 16-byte entries");
static_assert(cp_state::front_size == 256, "lookup stencil bakes a 255 mask");
static_assert(cp_state::front_contexts == TLB_NUM_CTX, "front cache follows the TLB context count");

static FORCE_INLINE size_t cp_front_context(uint64_t ctx_slot_base) {
    return static_cast<size_t>(ctx_slot_base / TLB_SET_SIZE);
}

static FORCE_INLINE void cp_front_put(cp_state *c, uint64_t ctx_slot_base, uint64_t pc, const void *fn) {
    c->front[cp_front_context(ctx_slot_base)][(pc >> 1) & (cp_state::front_size - 1)] = cp_front_entry{pc, fn};
}

static FORCE_INLINE void cp_front_purge(cp_state *c, uint64_t pc) {
    for (auto &bank : c->front) {
        auto &e = bank[(pc >> 1) & (cp_state::front_size - 1)];
        if (e.pc == pc) {
            e.pc = 1; // odd: architectural targets have bit 0 clear
        }
    }
}

static void cp_front_reset(cp_state *c) {
    for (auto &bank : c->front) {
        for (auto &e : bank) {
            e.pc = 1;
            e.fn = nullptr;
        }
    }
}

static FORCE_INLINE bool cp_hpage_traced(const cp_state *c, uint64_t hpage) {
    uint32_t s = cp_hpage_slot(hpage);
    const uint64_t tag = hpage + 1;
    while (c->traced_page[s] != 0) {
        if (c->traced_page[s] == tag) {
            return true;
        }
        s = (s + 1) & (cp_state::set_slots - 1);
    }
    return false;
}

static void cp_pending_link_add(cp_state *c, uint16_t pred_idx) {
    cp_trace &pred = c->pool[pred_idx];
    uint32_t slot = cp_pc_slot(pred.successor);
    const uint64_t tag = pred.successor + 1;
    while (c->pending_link_pc[slot] != 0 && c->pending_link_pc[slot] != tag) {
        slot = (slot + 1) & (cp_state::set_slots - 1);
    }
    if (c->pending_link_pc[slot] == 0) {
        c->pending_link_pc[slot] = tag;
        c->pending_link_trace[slot] = cp_state::none_link;
    }
    for (uint16_t p = c->pending_link_trace[slot]; p != cp_state::none_link; p = c->link_next[p]) {
        if (p == pred_idx) {
            return;
        }
    }
    c->link_next[pred_idx] = c->pending_link_trace[slot];
    c->pending_link_trace[slot] = pred_idx;
}

static void cp_retire_context_trace(cp_state *c, cp_trace &trace) {
    if (trace.dead) {
        return;
    }
    const uint16_t target = static_cast<uint16_t>(&trace - c->pool);
    trace.dead = true;
    cp_front_purge(c, trace.head);
    ++c->context_replacements;

    // A patched predecessor bypasses the head map. Restore every incoming
    // edge before treating the old trace as a miss, and retain the
    // predecessor as pending so a later same-context replacement can link.
    cp_heap_unprotect(&c->heap);
    for (uint32_t i = 0; i < c->ntraces; ++i) {
        cp_trace &pred = c->pool[i];
        if (pred.link_target == target) {
            cp_patch_branch(c->heap.base + pred.link_site, pred.link_kind, pred.link_addend,
                const_cast<uint8_t *>(static_cast<const uint8_t *>(c->continue_island)));
            cp_heap_lower(&c->heap, pred.link_site);
            pred.link_target = cp_state::none_link;
            ++c->links_severed;
            if (!pred.dead) {
                cp_pending_link_add(c, static_cast<uint16_t>(i));
            }
        }
    }
    cp_heap_protect_flush(&c->heap);
}

// Increment 1 has no inter-trace links, so killing is the dead flag alone;
// the head map reports absence and code is reclaimed at flush.
static void cp_write_hook(void *ctx, host_addr hstart, uint64_t length) {
    auto *c = static_cast<cp_state *>(ctx);
    if (c->ntraced_pages == 0 || length == 0) {
        return;
    }
    bool killed = false;
    const uint64_t first = static_cast<uint64_t>(hstart) & ~PAGE_OFFSET_MASK;
    const uint64_t last = (static_cast<uint64_t>(hstart) + length - 1) & ~PAGE_OFFSET_MASK;
    for (uint64_t hpage = first;; hpage += AR_PAGE_SIZE) {
        if (cp_hpage_traced(c, hpage)) {
            for (uint32_t i = 0; i < c->ntraces; ++i) {
                cp_trace &t = c->pool[i];
                if (t.dead) {
                    continue;
                }
                for (uint8_t j = 0; j < t.nhpages; ++j) {
                    if (t.hpage[j] == hpage) {
                        t.dead = true;
                        killed = true;
                        cp_front_purge(c, t.head);
                        ++c->invalidated;
                        break;
                    }
                }
            }
        }
        if (hpage == last) {
            break;
        }
    }
    if (killed) {
        // Sever links into dead traces: the head map already reports them
        // absent, but a patched predecessor branch reaches the body without
        // the map. Retarget those exits back to the island. During a
        // recording the heap is already writable and the finish or abort
        // flush covers the lowered watermark; otherwise publish here.
        if (!c->recording) {
            cp_heap_unprotect(&c->heap);
        }
        for (uint32_t i = 0; i < c->ntraces; ++i) {
            cp_trace &pred = c->pool[i];
            if (pred.link_target != cp_state::none_link && c->pool[pred.link_target].dead) {
                cp_patch_branch(c->heap.base + pred.link_site, pred.link_kind, pred.link_addend,
                    const_cast<uint8_t *>(static_cast<const uint8_t *>(c->continue_island)));
                cp_heap_lower(&c->heap, pred.link_site);
                pred.link_target = cp_state::none_link;
                ++c->links_severed;
            }
        }
        if (!c->recording) {
            cp_heap_protect_flush(&c->heap);
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle.

static void cp_flush(cp_state *c) {
    c->heap.curr = c->heap_reset_curr;
    c->ntraces = 0;
    std::memset(c->installed_pc, 0, sizeof(c->installed_pc));
    std::memset(c->traced_page, 0, sizeof(c->traced_page));
    std::memset(c->pending_link_pc, 0, sizeof(c->pending_link_pc));
    cp_front_reset(c);
    c->ntraced_pages = 0;
    c->recording = false;
    ++c->flushes;
}

static void cp_fusion_print_terminal_stats(const cp_state *c);

static void cp_free(void *p) {
    auto *c = static_cast<cp_state *>(p);
    if (std::getenv("CP_STATS") != nullptr) {
        std::fprintf(stderr,
            "cp: installed %llu empty-marked %llu invalidated %llu flushes %llu emitted %llu bytes "
            "compile-ms %llu entries %llu call-entries %llu links %llu severed %llu "
            "context-misses %llu context-replacements %llu context-link-rejects %llu\n",
            static_cast<unsigned long long>(c->installed), static_cast<unsigned long long>(c->empty_marked),
            static_cast<unsigned long long>(c->invalidated), static_cast<unsigned long long>(c->flushes),
            static_cast<unsigned long long>(c->emitted_bytes), static_cast<unsigned long long>(c->compile_ns / 1000000),
            static_cast<unsigned long long>(c->entries), static_cast<unsigned long long>(c->call_entries),
            static_cast<unsigned long long>(c->links), static_cast<unsigned long long>(c->links_severed),
            static_cast<unsigned long long>(c->context_misses),
            static_cast<unsigned long long>(c->context_replacements),
            static_cast<unsigned long long>(c->context_link_rejects));
        std::fprintf(stderr,
            "cp: fin cyclic %llu dynamic %llu page %llu installed %llu maxlen %llu uncompilable %llu trap %llu "
            "evictions %llu\n",
            static_cast<unsigned long long>(c->fin_cyclic), static_cast<unsigned long long>(c->fin_dynamic),
            static_cast<unsigned long long>(c->fin_page), static_cast<unsigned long long>(c->fin_installed),
            static_cast<unsigned long long>(c->fin_maxlen), static_cast<unsigned long long>(c->fin_uncompilable),
            static_cast<unsigned long long>(c->fin_trap), static_cast<unsigned long long>(c->evictions));
        std::fprintf(stderr, "cp: continue-enters %llu continue-trips %llu\n",
            static_cast<unsigned long long>(c->continue_enters), static_cast<unsigned long long>(c->continue_trips));
        std::fprintf(stderr, "cp: carried %llu\n", static_cast<unsigned long long>(c->carried));
        std::fprintf(stderr, "cp: fusion rewrites %llu guest-insns %llu old-bytes %llu new-bytes %llu\n",
            static_cast<unsigned long long>(c->fusion_rewrites),
            static_cast<unsigned long long>(c->fusion_guest_insns),
            static_cast<unsigned long long>(c->fusion_old_bytes),
            static_cast<unsigned long long>(c->fusion_new_bytes));
        cp_fusion_print_terminal_stats(c);
        for (int rank = 0; rank < 10; ++rank) {
            uint32_t best = 0;
            const cp_trace *bt = nullptr;
            for (uint32_t i = 0; i < c->ntraces; ++i) {
                if (c->pool[i].exec_count > best) {
                    best = c->pool[i].exec_count;
                    bt = &c->pool[i];
                }
            }
            if (bt == nullptr) {
                break;
            }
            std::fprintf(stderr, "cp: hot trace head=%llx len=%u entries=%u succ=%llx%s%s\n",
                static_cast<unsigned long long>(bt->head), bt->len, bt->exec_count,
                static_cast<unsigned long long>(bt->successor), bt->link_site == 0 ? " (no-link-site)" : "",
                bt->carried ? " (carried)" : "");
            const_cast<cp_trace *>(bt)->exec_count = 0;
        }
        std::fprintf(stderr,
            "cp: tick-bails %llu ctx-bails %llu page-bails %llu vh-bails %llu lookup-misses %llu "
            "branch-bails %llu mem-bails %llu fp-soft %llu terminal-exits %llu\n",
            static_cast<unsigned long long>(c->tick_bails), static_cast<unsigned long long>(c->ctx_bails),
            static_cast<unsigned long long>(c->page_bails), static_cast<unsigned long long>(c->vh_bails),
            static_cast<unsigned long long>(c->lookup_misses), static_cast<unsigned long long>(c->branch_bails),
            static_cast<unsigned long long>(c->mem_bails), static_cast<unsigned long long>(c->fp_soft_calls),
            static_cast<unsigned long long>(c->terminal_exits));
    }
    cp_heap_free(&c->heap);
    delete c;
}

template <typename STATE_ACCESS>
TC_CALLCONV static execute_status cp_continue(STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS);
template <typename STATE_ACCESS>
TC_CALLCONV static execute_status cp_continue_cold(STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS);

static cp_state *cp_get(penumbra_state &penumbra, const void *continue_fn, const void *continue_cold_fn) {
#if defined(__x86_64__)
    static const bool fma_stencils_initialized = [] {
        __builtin_cpu_init();
        if (__builtin_cpu_supports("fma")) {
            cp_enable_x86_fma_stencils();
        }
        return true;
    }();
    (void) fma_stencils_initialized;
#endif
    if (penumbra.tc_state == nullptr) {
        auto *c = new cp_state{};
        if (cp_heap_init(&c->heap, 64u << 20) != 0) {
            delete c;
            return nullptr;
        }
        // The far-jump island through which every exit reaches the
        // interpreter continuation, emitted once per heap, plus one counting
        // island per bail cause (cold paths only).
        cp_heap_unprotect(&c->heap);
        const uint64_t imm[2] = {reinterpret_cast<uint64_t>(continue_fn), 0};
        const uint64_t imm_cold[2] = {reinterpret_cast<uint64_t>(continue_cold_fn), 0};
        uint8_t *island_cont[2] = {nullptr, nullptr};
        c->continue_island = cp_emit(&c->heap, &cp_s_cp_far_jump, imm, island_cont);
        c->continue_cold_island = cp_emit(&c->heap, &cp_s_cp_far_jump, imm_cold, island_cont);
        // Bail causes that must not re-enter (a failed entry or short
        // countdown would fail again immediately) resume cold; exits and
        // lookup misses go through the entering continuation.
        const auto counting_island = [&](uint64_t *counter, const uint64_t (&target)[2]) -> const void * {
            const uint64_t imm_count[2] = {reinterpret_cast<uint64_t>(counter), 0};
            uint8_t *fall[2] = {nullptr, nullptr};
            const void *at = cp_emit(&c->heap, &cp_s_cp_count, imm_count, fall);
            cp_emit(&c->heap, &cp_s_cp_far_jump, target, island_cont);
            return at;
        };
        c->tick_island = counting_island(&c->tick_bails, imm_cold);
        c->ctx_island = counting_island(&c->ctx_bails, imm_cold);
        c->page_island = counting_island(&c->page_bails, imm_cold);
        c->vh_island = counting_island(&c->vh_bails, imm_cold);
        c->miss_island = counting_island(&c->lookup_misses, imm);
        c->branch_bail_island = counting_island(&c->branch_bails, imm);
        c->mem_bail_island = counting_island(&c->mem_bails, imm);
        c->mem_bail_cold_island = counting_island(&c->mem_bails, imm_cold);
        c->terminal_island = counting_island(&c->terminal_exits, imm);
        cp_heap_protect_flush(&c->heap);
        c->heap_reset_curr = c->heap.curr;
        cp_front_reset(c);
        penumbra.tc_state = c;
        penumbra.tc_state_free = &cp_free;
    }
    return static_cast<cp_state *>(penumbra.tc_state);
}

// One-time env probe for the formation/entry debug log.
static bool cp_log_enabled() {
    static const bool enabled = std::getenv("CP_LOG") != nullptr;
    return enabled;
}

static bool cp_fp_enabled() {
    static const bool enabled = std::getenv("CP_FP_DISABLE") == nullptr;
    return enabled;
}

static bool cp_imm_enabled() {
    static const bool enabled = std::getenv("CP_IMM_DISABLE") == nullptr;
    return enabled;
}

// ---------------------------------------------------------------------------
// Formation: the emitter-facing former the selection include drives.

/// \brief Finds a stencil's bail branch (the continuation-1 patch), the one
/// site guards re-point at their bail blocks.
static const cp_patch_t *cp_cont_patch(const cp_stencil_t *st, uint16_t ordinal) {
    for (uint16_t i = 0; i < st->npatches; ++i) {
        const cp_patch_t *p = &st->patches[i];
        if ((p->kind == CP_P_JUMP26 || p->kind == CP_P_JMPREL32) && p->ordinal == ordinal) {
            return p;
        }
    }
    return nullptr;
}

static const cp_patch_t *cp_bail_patch(const cp_stencil_t *st) {
    return cp_cont_patch(st, 1);
}

static FORCE_INLINE void cp_save_checkpoint(const cp_state *c, cp_state::cp_form_checkpoint &p) {
    p.heap_curr = c->heap.curr;
    std::memcpy(p.reg_slot, c->reg_slot, sizeof(p.reg_slot));
    std::memcpy(p.slot_guest, c->slot_guest, sizeof(p.slot_guest));
    std::memcpy(p.last_used, c->rec_last_used, sizeof(p.last_used));
    p.reg_dirty = c->reg_dirty;
    p.nslots_used = c->nslots_used;
    p.use_clock = c->rec_use_clock;
    p.log_len = c->rec_log_len;
    p.guest_slots = c->rec_guest_slots;
    p.scratch_slots = c->rec_scratch_slots;
    p.nbails = c->nbails;
    p.carry_ok = c->rec_carry_ok;
    p.evictions = c->evictions;
}

static FORCE_INLINE void cp_restore_checkpoint(cp_state *c, const cp_state::cp_form_checkpoint &p) {
    c->heap.curr = p.heap_curr;
    std::memcpy(c->reg_slot, p.reg_slot, sizeof(c->reg_slot));
    std::memcpy(c->slot_guest, p.slot_guest, sizeof(c->slot_guest));
    std::memcpy(c->rec_last_used, p.last_used, sizeof(c->rec_last_used));
    c->reg_dirty = p.reg_dirty;
    c->nslots_used = p.nslots_used;
    c->rec_use_clock = p.use_clock;
    c->rec_log_len = p.log_len;
    c->rec_guest_slots = p.guest_slots;
    c->rec_scratch_slots = p.scratch_slots;
    c->nbails = p.nbails;
    c->rec_carry_ok = p.carry_ok;
    c->evictions = p.evictions;
}

struct cp_former {
    cp_state *c;
    uint64_t pc; // guest vaddr of the instruction being recorded

    // Slot-level emission. cont[0] null means fallthrough (elided). Every
    // body emission is also logged so an eligible cyclic close can replay
    // the body with first-use loads hoisted to a preheader (loop carry);
    // the markers tag the pending record as a hoistable load or as the
    // guard owning a bails[] entry whose site the replay re-records.
    int8_t log_next_load = -1;
    int16_t log_next_bail = -1;
    int16_t log_next_bail2 = -1;
    int16_t log_next_resume_bail = -1;
    uint8_t *emit1(const cp_stencil_t *st, uint64_t imm0 = 0, uint64_t imm1 = 0, uint8_t *bail = nullptr,
        uint8_t *bail2 = nullptr) {
        const uint64_t imm[2] = {imm0, imm1};
        uint8_t *cont[3] = {nullptr, bail, bail2};
        uint8_t *at = cp_emit(&c->heap, st, imm, cont);
        if (at == nullptr) {
            c->rec_failed = true;
        }
        if (c->rec_log_len < cp_state::max_log) {
            auto &r = c->rec_log[c->rec_log_len++];
            r.st = st;
            r.imm0 = imm0;
            r.imm1 = imm1;
            r.bail_index = log_next_bail;
            r.bail_index2 = log_next_bail2;
            r.resume_bail_index = log_next_resume_bail;
            r.load_slot = log_next_load;
        } else {
            c->rec_carry_ok = false;
        }
        log_next_bail = -1;
        log_next_bail2 = -1;
        log_next_resume_bail = -1;
        log_next_load = -1;
        return at;
    }

    // Guest-register slot allocation, RVVM's guest-indexed cache with its
    // last_used eviction: once every slot fills, the least-recently-used
    // slot not locked by the current instruction spills (a gxs store when
    // dirty) and remaps. Slots this instruction touched are locked so an
    // operand is never evicted mid-instruction.
    uint32_t locked = 0;

    void touch(int slot) {
        locked |= 1u << static_cast<uint32_t>(slot);
        c->rec_last_used[slot] = ++c->rec_use_clock;
    }

    int take_slot() {
        if (c->nslots_used < cp_state::nslots) {
            return c->nslots_used++;
        }
        int best = -1;
        uint32_t best_used = UINT32_MAX;
        for (int s = 0; s < static_cast<int>(cp_state::nslots); ++s) {
            if ((locked & (1u << static_cast<uint32_t>(s))) != 0) {
                continue;
            }
            const uint32_t used = c->slot_guest[s] == 0xff ? 0 : c->rec_last_used[s];
            if (used < best_used) {
                best_used = used;
                best = s;
            }
        }
        if (best < 0) {
            c->rec_failed = true; // every slot locked by this instruction
            return -1;
        }
        const uint8_t old = c->slot_guest[best];
        if (old != 0xff) {
            if ((c->reg_dirty & (1u << static_cast<uint32_t>(best))) != 0 && old != 0) {
                emit1(cp_gxs_table[best][old - 1]);
                c->reg_dirty &= ~(1u << static_cast<uint32_t>(best));
            }
            c->reg_slot[old] = -1;
            ++c->evictions;
        }
        return best;
    }

    void carry_blocked(const char *why, int slot) {
        if (c->rec_carry_ok && cp_log_enabled()) [[unlikely]] {
            std::fprintf(stderr, "cp-nocarry head=%llx vpc=%llx %s slot=%d\n",
                static_cast<unsigned long long>(c->rec_head), static_cast<unsigned long long>(pc), why, slot);
        }
        c->rec_carry_ok = false;
    }

    void bind_guest(int slot) {
        if ((c->rec_scratch_slots & (1u << static_cast<uint32_t>(slot))) != 0 ||
            (c->rec_guest_slots & (1u << static_cast<uint32_t>(slot))) != 0) {
            carry_blocked("guest-rebind", slot); // a carried value would not survive
        }
        c->rec_guest_slots |= 1u << static_cast<uint32_t>(slot);
    }

    int alloc_src(uint8_t reg) {
        if (c->reg_slot[reg] >= 0) {
            const int slot = c->reg_slot[reg];
            touch(slot);
            return slot;
        }
        const int slot = take_slot();
        if (slot < 0) {
            return -1;
        }
        bind_guest(slot);
        c->slot_guest[slot] = reg;
        c->reg_slot[reg] = static_cast<int8_t>(slot);
        touch(slot);
        log_next_load = static_cast<int8_t>(slot);
        if (reg == 0) {
            emit1(cp_li_table[slot], 0);
        } else {
            emit1(cp_gxl_table[slot][reg - 1]);
        }
        return slot;
    }

    // Destination slot: same mapping, no load needed when first written.
    int alloc_dst(uint8_t reg) {
        if (c->reg_slot[reg] >= 0) {
            const int slot = c->reg_slot[reg];
            c->reg_dirty |= 1u << static_cast<uint32_t>(slot);
            touch(slot);
            return slot;
        }
        const int slot = take_slot();
        if (slot < 0) {
            return -1;
        }
        bind_guest(slot);
        c->slot_guest[slot] = reg;
        c->reg_slot[reg] = static_cast<int8_t>(slot);
        c->reg_dirty |= 1u << static_cast<uint32_t>(slot);
        touch(slot);
        return slot;
    }

    // A transient slot for materialized immediates and address arithmetic.
    int alloc_scratch() {
        // Prefer reusing a freed scratch slot over consuming a fresh one:
        // scratch churn stays confined to the same slots, fresh slots stay
        // available for guest bindings, and the guest/scratch sets stay
        // disjoint, which is what keeps loops loop-carry eligible.
        for (int slot = 0; slot < static_cast<int>(c->nslots_used); ++slot) {
            if (c->slot_guest[slot] == 0xff && c->rec_last_used[slot] == 0 &&
                (locked & (1u << static_cast<uint32_t>(slot))) == 0) {
                touch(slot);
                return slot;
            }
        }
        const int slot = take_slot();
        if (slot < 0) {
            return -1;
        }
        if ((c->rec_guest_slots & (1u << static_cast<uint32_t>(slot))) != 0) {
            carry_blocked("scratch-on-guest", slot); // would clobber a carried value
        }
        c->rec_scratch_slots |= 1u << static_cast<uint32_t>(slot);
        c->slot_guest[slot] = 0xff;
        touch(slot);
        return slot;
    }
    int alloc_fixed_scratch(int slot) {
        if ((locked & (1u << static_cast<uint32_t>(slot))) != 0) {
            c->rec_failed = true;
            return -1;
        }
        if (slot >= static_cast<int>(c->nslots_used)) {
            c->nslots_used = static_cast<uint8_t>(slot + 1);
        }
        const uint8_t old = c->slot_guest[slot];
        if (old != 0xff) {
            if ((c->reg_dirty & (1u << static_cast<uint32_t>(slot))) != 0 && old != 0) {
                emit1(cp_gxs_table[slot][old - 1]);
                c->reg_dirty &= ~(1u << static_cast<uint32_t>(slot));
            }
            c->reg_slot[old] = -1;
            ++c->evictions;
            carry_blocked("fixed-scratch-on-guest", slot);
        }
        c->rec_scratch_slots |= 1u << static_cast<uint32_t>(slot);
        c->slot_guest[slot] = 0xff;
        touch(slot);
        return slot;
    }
    void free_scratch(int slot) {
        if (slot >= 0 && c->slot_guest[slot] == 0xff) {
            c->rec_last_used[slot] = 0; // preferred victim
        }
    }

    // Guest-level primitives, called from cp-select.inc.
    void reg3(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS][CP_NSLOTS], uint8_t rd, uint8_t rs1, uint8_t rs2) {
        const int s1 = alloc_src(rs1);
        const int s2 = alloc_src(rs2);
        if (rd == 0 || c->rec_failed) {
            return; // reads folded away; x0 writes are dropped
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit1(tab[d][s1][s2]);
    }

    void move(uint8_t rd, uint8_t rs) {
        const int s = alloc_src(rs);
        if (rd == 0 || c->rec_failed) {
            return;
        }
        if (rd == rs) {
            return;
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit1(cp_mv_table[d][s]);
    }

    void reg2i(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS][CP_NSLOTS], uint8_t rd, uint8_t rs1,
        uint64_t imm) {
        const int s1 = alloc_src(rs1);
        const int t = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        emit1(cp_li_table[t], imm);
        if (rd != 0) {
            const int d = alloc_dst(rd);
            if (c->rec_failed) {
                return;
            }
            emit1(tab[d][s1][t]);
        }
        free_scratch(t);
    }

    void reg2directi(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS],
        const cp_stencil_t *const (&fallback)[CP_NSLOTS][CP_NSLOTS][CP_NSLOTS], uint8_t rd, uint8_t rs1, uint64_t imm) {
        if (!cp_imm_enabled()) {
            reg2i(fallback, rd, rs1, imm);
            return;
        }
        const int s = alloc_src(rs1);
        if (rd == 0 || c->rec_failed) {
            return;
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit1(tab[d][s], imm);
    }

    void fused_slli_add(const cp_stencil_t *const (*table)[CP_NSLOTS], uint8_t rd, uint8_t rs2) {
        const int d = alloc_src(rd);
        const int s = alloc_src(rs2);
        if (c->rec_failed) {
            return;
        }
        const int out = alloc_dst(rd);
        if (c->rec_failed || out != d) {
            c->rec_failed = true;
            return;
        }
        emit1(table[d][s]);
    }

    void fused_reg2(const cp_stencil_t *const (*table)[CP_NSLOTS], uint8_t rd, uint8_t rs1) {
        const int s = alloc_src(rs1);
        if (c->rec_failed) {
            return;
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit1(table[d][s]);
    }

    void fused_zext32_add(const cp_stencil_t *const (*table)[CP_NSLOTS][CP_NSLOTS], uint8_t rd, uint8_t rs1,
        uint8_t rs2) {
        const int s = alloc_src(rs1);
        const int a = alloc_src(rs2);
        if (c->rec_failed) {
            return;
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit1(table[d][s][a]);
    }

    void fused_shift_extract_add(const cp_stencil_t *const (*table)[CP_NSLOTS][CP_NSLOTS], uint8_t rd1,
        uint8_t rd2, uint8_t rs3) {
        const int s = alloc_src(rd2);
        const int a = alloc_src(rs3);
        if (c->rec_failed) {
            return;
        }
        const int d1 = alloc_dst(rd1);
        const int d2 = alloc_dst(rd2);
        if (c->rec_failed || d2 != s) {
            c->rec_failed = true;
            return;
        }
        emit1(table[d1][d2][a]);
    }

    void fused_scaled_lw(const cp_stencil_t *const (*table)[CP_NSLOTS][CP_NSLOTS], uint8_t address_rd,
        uint8_t add_rs, uint8_t load_rd) {
        const int address = alloc_src(address_rd);
        const int add = alloc_src(add_rs);
        if (c->rec_failed) {
            return;
        }
        const int address_out = alloc_dst(address_rd);
        if (c->rec_failed || address_out != address) {
            c->rec_failed = true;
            return;
        }
        const bool fresh = c->reg_slot[load_rd] < 0;
        const int load = alloc_dst(load_rd);
        if (c->rec_failed) {
            return;
        }
        const uint32_t bail_dirty = fresh ? (c->reg_dirty & ~(1u << static_cast<uint32_t>(load))) : c->reg_dirty;
        emit_guarded(table[address][add][load], bail_dirty, cp_front_context(c->rec_ctx_slot_base));
    }

    void fused_lbu_bne(const cp_stencil_t *const (*table)[CP_NSLOTS][CP_NSLOTS], uint8_t rd, uint8_t rs1,
        uint64_t imm, uint8_t compare_rs, uint32_t memory_pending, int64_t branch_delta, uint32_t branch_pending) {
        if (c->nbails + 2 > cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        int scratch = -1;
        const int base = address(rs1, imm, scratch);
        const int compare = alloc_src(compare_rs);
        if (c->rec_failed) {
            return;
        }
        const bool fresh = c->reg_slot[rd] < 0;
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        const uint32_t memory_dirty = fresh ? (c->reg_dirty & ~(1u << static_cast<uint32_t>(d))) : c->reg_dirty;
        const uint32_t memory_index = c->nbails;
        const uint32_t branch_index = memory_index + 1;
        log_next_bail = static_cast<int16_t>(memory_index);
        log_next_bail2 = static_cast<int16_t>(branch_index);
        auto *placeholder = reinterpret_cast<uint8_t *>(this);
        const cp_stencil_t *st = table[d][base][compare];
        uint8_t *at = emit1(st, cp_front_context(c->rec_ctx_slot_base), 0, placeholder, placeholder);
        if (at == nullptr) {
            return;
        }
        const cp_patch_t *memory_patch = cp_cont_patch(st, 1);
        const cp_patch_t *branch_patch = cp_cont_patch(st, 2);
        if (memory_patch == nullptr || branch_patch == nullptr) {
            c->rec_failed = true;
            return;
        }
        cp_bail &memory = c->bails[c->nbails++];
        memory.guard_site = static_cast<uint32_t>((at + memory_patch->offset) - c->heap.base);
        memory.guard_kind = memory_patch->kind;
        memory.guard_addend = memory_patch->addend;
        memory.delta = static_cast<int64_t>(pc - c->rec_head);
        memory.pending = memory_pending;
        memory.dirty = memory_dirty;
        std::memcpy(memory.slot_guest, c->slot_guest, sizeof(memory.slot_guest));
        memory.is_branch = false;
        memory.is_fp = false;
        memory.is_cold = false;

        cp_bail &branch = c->bails[c->nbails++];
        branch.guard_site = static_cast<uint32_t>((at + branch_patch->offset) - c->heap.base);
        branch.guard_kind = branch_patch->kind;
        branch.guard_addend = branch_patch->addend;
        branch.delta = branch_delta;
        branch.pending = branch_pending;
        branch.dirty = c->reg_dirty;
        std::memcpy(branch.slot_guest, c->slot_guest, sizeof(branch.slot_guest));
        branch.is_branch = true;
        branch.is_fp = false;
        branch.is_cold = false;
        free_scratch(scratch);
    }

    void li(uint8_t rd, uint64_t value) {
        if (rd == 0) {
            return;
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit1(cp_li_table[d], value);
    }

    // Base+imm address into a slot; returns the slot with the address.
    int address(uint8_t rs1, uint64_t imm, int &scratch) {
        const int s1 = alloc_src(rs1);
        scratch = -1;
        if (imm == 0 || c->rec_failed) {
            return s1;
        }
        scratch = alloc_scratch();
        if (c->rec_failed) {
            return -1;
        }
        emit1(cp_li_table[scratch], imm);
        emit1(cp_add_table[scratch][s1][scratch]);
        return scratch;
    }

    void load(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS], uint8_t rd, uint8_t rs1, uint64_t imm) {
        int scratch = -1;
        const int base = address(rs1, imm, scratch);
        if (c->rec_failed) {
            return;
        }
        if (rd == 0) {
            // A load to x0 still probes and can fault: bail-only shape,
            // discarding the value into a scratch slot.
            const int t = scratch >= 0 ? scratch : alloc_scratch();
            if (c->rec_failed) {
                return;
            }
            emit_guarded(tab[t][base], c->reg_dirty, cp_front_context(c->rec_ctx_slot_base));
            free_scratch(t);
            return;
        }
        // The bail runs when the load did NOT execute, so a freshly bound
        // destination must not be in the bail's dirty set: its slot register
        // is uninitialized there, and a faulting load leaves rd unchanged.
        // An aliased destination keeps its bit: the slot still holds the
        // architecturally current value at the bail.
        const bool fresh = c->reg_slot[rd] < 0;
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit_guarded(tab[d][base], fresh ? (c->reg_dirty & ~(1u << static_cast<uint32_t>(d))) : c->reg_dirty,
            cp_front_context(c->rec_ctx_slot_base));
        free_scratch(scratch);
    }

    void store(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS], uint8_t rs1, uint8_t rs2, uint64_t imm) {
        int scratch = -1;
        const int base = address(rs1, imm, scratch);
        const int val = alloc_src(rs2);
        if (c->rec_failed) {
            return;
        }
        emit_guarded(tab[base][val], c->reg_dirty, cp_front_context(c->rec_ctx_slot_base));
        free_scratch(scratch);
    }

    // Emits a hit-or-bail stencil, deferring the bail block to finish.
    // bail_dirty is the dirty set the bail block may store: the caller
    // excludes destinations the guarded instruction has not yet written.
    void emit_guarded(const cp_stencil_t *st, uint32_t bail_dirty, uint64_t imm0 = 0) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        log_next_bail = static_cast<int16_t>(c->nbails);
        uint8_t *at = emit1(st, imm0, 0, reinterpret_cast<uint8_t *>(this)); // placeholder target
        if (at == nullptr) {
            return;
        }
        // Locate the bail patch (ordinal 1) of this stencil to re-patch at
        // finish, once the grouped bail blocks exist.
        if (const cp_patch_t *p = cp_bail_patch(st); p != nullptr) {
            cp_bail &b = c->bails[c->nbails++];
            b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
            b.guard_kind = p->kind;
            b.guard_addend = p->addend;
            b.delta = static_cast<int64_t>(pc - c->rec_head);
            b.pending = c->rec_len; // instructions fully retired before this one
            b.dirty = bail_dirty;
            std::memcpy(b.slot_guest, c->slot_guest, sizeof(b.slot_guest));
            b.is_branch = false;
            b.is_fp = false;
            b.is_cold = false;
            return;
        }
        c->rec_failed = true; // stencil without a bail continuation
    }

    // Guarded binary FP arithmetic. Operands and the result use transient
    // roster slots, so the integer register cache remains independent. A
    // hard-guard miss is deferred to a soft_only helper block that rejoins
    // after the hard-result store; architectural failures leave from there
    // for portable re-execution with this instruction still pending.
    void fp_binary(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS], uint32_t insn) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        const int d = alloc_scratch();
        const int s = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        const uint32_t rd = insn_get_rd(insn);
        const uint32_t rs1 = insn_get_rs1(insn);
        const uint32_t rs2 = insn_get_rs2(insn);
        emit1(cp_fxl_table[d][rs1]);
        emit1(cp_fxl_table[s][rs2]);

        const uint32_t bail_index = c->nbails;
        log_next_bail = static_cast<int16_t>(bail_index);
        uint8_t *at = emit1(tab[d][s], 0, 0, reinterpret_cast<uint8_t *>(this));
        if (at == nullptr) {
            return;
        }
        const cp_patch_t *const p = cp_bail_patch(tab[d][s]);
        if (p == nullptr) {
            c->rec_failed = true;
            return;
        }
        cp_bail &b = c->bails[c->nbails++];
        b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
        b.guard_kind = p->kind;
        b.guard_addend = p->addend;
        b.delta = static_cast<int64_t>(pc - c->rec_head);
        b.pending = c->rec_len;
        b.dirty = c->reg_dirty;
        std::memcpy(b.slot_guest, c->slot_guest, sizeof(b.slot_guest));
        b.is_branch = false;
        b.is_fp = true;
        b.is_cold = false;
        b.fp_insn = insn;

        log_next_resume_bail = static_cast<int16_t>(bail_index);
        emit1(cp_fxs_table[d][rd]);
        b.fp_resume = static_cast<uint32_t>(c->heap.curr);
        free_scratch(s);
        free_scratch(d);
    }

    void fp_unary(const cp_stencil_t *const (&tab)[CP_NSLOTS], uint32_t insn) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        const int d = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        const uint32_t rd = insn_get_rd(insn);
        emit1(cp_fxl_table[d][insn_get_rs1(insn)]);

        const uint32_t bail_index = c->nbails;
        log_next_bail = static_cast<int16_t>(bail_index);
        uint8_t *at = emit1(tab[d], 0, 0, reinterpret_cast<uint8_t *>(this));
        if (at == nullptr) {
            return;
        }
        const cp_patch_t *const p = cp_bail_patch(tab[d]);
        if (p == nullptr) {
            c->rec_failed = true;
            return;
        }
        cp_bail &b = c->bails[c->nbails++];
        b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
        b.guard_kind = p->kind;
        b.guard_addend = p->addend;
        b.delta = static_cast<int64_t>(pc - c->rec_head);
        b.pending = c->rec_len;
        b.dirty = c->reg_dirty;
        std::memcpy(b.slot_guest, c->slot_guest, sizeof(b.slot_guest));
        b.is_branch = false;
        b.is_fp = true;
        b.is_cold = false;
        b.fp_insn = insn;

        log_next_resume_bail = static_cast<int16_t>(bail_index);
        emit1(cp_fxs_table[d][rd]);
        b.fp_resume = static_cast<uint32_t>(c->heap.curr);
        free_scratch(d);
    }

    void fp_soft(uint32_t insn) {
        emit_guarded(&cp_s_cp_fp_always_soft, c->reg_dirty);
        if (c->rec_failed) {
            return;
        }
        cp_bail &b = c->bails[c->nbails - 1];
        b.is_fp = true;
        b.fp_insn = insn;
        b.fp_resume = static_cast<uint32_t>(c->heap.curr);
    }

    template <typename TABLE>
    void fp_ternary(const TABLE &tab, uint32_t insn) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        // Pin the third operand to the last roster slot. This reduces each
        // fused family from a cubic placement matrix to a quadratic one.
        const int s3 = alloc_fixed_scratch(CP_NSLOTS - 1);
        const int d = alloc_scratch();
        const int s2 = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        const uint32_t rd = insn_get_rd(insn);
        emit1(cp_fxl_table[d][insn_get_rs1(insn)]);
        emit1(cp_fxl_table[s2][insn_get_rs2(insn)]);
        emit1(cp_fxl_table[s3][insn_get_rs3(insn)]);

        const uint32_t bail_index = c->nbails;
        log_next_bail = static_cast<int16_t>(bail_index);
        uint8_t *at = emit1(tab[d][s2], 0, 0, reinterpret_cast<uint8_t *>(this));
        if (at == nullptr) {
            return;
        }
        const cp_patch_t *const p = cp_bail_patch(tab[d][s2]);
        if (p == nullptr) {
            c->rec_failed = true;
            return;
        }
        cp_bail &b = c->bails[c->nbails++];
        b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
        b.guard_kind = p->kind;
        b.guard_addend = p->addend;
        b.delta = static_cast<int64_t>(pc - c->rec_head);
        b.pending = c->rec_len;
        b.dirty = c->reg_dirty;
        std::memcpy(b.slot_guest, c->slot_guest, sizeof(b.slot_guest));
        b.is_branch = false;
        b.is_fp = true;
        b.is_cold = false;
        b.fp_insn = insn;

        log_next_resume_bail = static_cast<int16_t>(bail_index);
        emit1(cp_fxs_table[d][rd]);
        b.fp_resume = static_cast<uint32_t>(c->heap.curr);
        free_scratch(s3);
        free_scratch(s2);
        free_scratch(d);
    }

    // Exact FP families need only the architectural FS check. Once it
    // succeeds their integer/soft-float stencil has no hard-FPU guard and
    // therefore no soft-only fallback. FS-off leaves cold so the portable
    // interpreter raises the architectural exception.
    void fp_exact_guard() {
        emit_guarded(&cp_s_cp_fp_fs_guard, c->reg_dirty);
        if (!c->rec_failed) {
            c->bails[c->nbails - 1].is_cold = true;
        }
    }

    void fp_exact_binary(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS], uint32_t insn) {
        const int d = alloc_scratch();
        const int s = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        fp_exact_guard();
        emit1(cp_fxl_table[d][insn_get_rs1(insn)]);
        emit1(cp_fxl_table[s][insn_get_rs2(insn)]);
        emit1(tab[d][s]);
        emit1(cp_fxs_table[d][insn_get_rd(insn)]);
        free_scratch(s);
        free_scratch(d);
    }

    void fp_exact_cmp(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS], uint32_t insn) {
        const uint8_t rd = insn_get_rd(insn);
        const int d = rd == 0 ? alloc_scratch() : alloc_dst(rd);
        const int s = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        fp_exact_guard();
        emit1(cp_fxl_table[d][insn_get_rs1(insn)]);
        emit1(cp_fxl_table[s][insn_get_rs2(insn)]);
        emit1(tab[d][s]);
        free_scratch(s);
        if (rd == 0) {
            free_scratch(d);
        }
    }

    void fp_exact_unary_x(const cp_stencil_t *const (&tab)[CP_NSLOTS], uint32_t insn) {
        const uint8_t rd = insn_get_rd(insn);
        const int d = rd == 0 ? alloc_scratch() : alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        fp_exact_guard();
        emit1(cp_fxl_table[d][insn_get_rs1(insn)]);
        emit1(tab[d]);
        if (rd == 0) {
            free_scratch(d);
        }
    }

    // CSR (the hot FP CSRs): guarded like loads, a bail meaning the
    // instruction did not execute (FS off), so a fresh destination stays
    // out of the bail's dirty set. rd=x0 lands in a scratch slot (the slot
    // write is architecturally invisible); the read-only table serves
    // csrrs/csrrc with rs1=x0, which must not write the CSR; csrrw with
    // rs1=x0 writes zero, so it takes the full table with a zero slot.
    void csr(const cp_stencil_t *const (*tab)[CP_NSLOTS], const cp_stencil_t *const *rtab, uint8_t rd, uint8_t rs1) {
        int s1 = -1;
        if (rtab == nullptr || rs1 != 0) {
            s1 = alloc_src(rs1);
        }
        if (c->rec_failed) {
            return;
        }
        const bool fresh = rd == 0 || c->reg_slot[rd] < 0;
        const int d = rd == 0 ? alloc_scratch() : alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        const uint32_t bail_dirty = fresh ? (c->reg_dirty & ~(1u << static_cast<uint32_t>(d))) : c->reg_dirty;
        if (s1 < 0) {
            emit_guarded(rtab[d], bail_dirty);
        } else {
            emit_guarded(tab[d][s1], bail_dirty);
        }
        if (rd == 0) {
            free_scratch(d);
        }
    }

    // Branch guard with the recorded direction as fallthrough.
    void guard_branch(const cp_stencil_t *st, int64_t off_delta) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        log_next_bail = static_cast<int16_t>(c->nbails);
        uint8_t *at = emit1(st, 0, 0, reinterpret_cast<uint8_t *>(this));
        if (at == nullptr) {
            return;
        }
        if (const cp_patch_t *p = cp_bail_patch(st); p != nullptr) {
            cp_bail &b = c->bails[c->nbails++];
            b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
            b.guard_kind = p->kind;
            b.guard_addend = p->addend;
            b.delta = off_delta;
            b.pending = c->rec_len + 1; // the branch itself retires on exit
            b.dirty = c->reg_dirty;
            std::memcpy(b.slot_guest, c->slot_guest, sizeof(b.slot_guest));
            b.is_branch = true;
            b.is_fp = false;
            b.is_cold = false;
            return;
        }
        c->rec_failed = true;
    }

    // Branches lag one record call: the direction is the next pc.
    void branch(const cp_stencil_t *const (&tab)[CP_NSLOTS][CP_NSLOTS],
        const cp_stencil_t *const (&comp)[CP_NSLOTS][CP_NSLOTS], uint8_t rs1, uint8_t rs2, uint64_t taken_target,
        uint8_t size) {
        c->have_pending_branch = true;
        c->pb_vaddr = pc;
        c->pb_taken_target = taken_target;
        c->pb_tab = tab;
        c->pb_comp = comp;
        c->pb_rs1 = rs1;
        c->pb_rs2 = rs2;
        c->pb_size = size;
    }

    // Direct jump: recording continues at the target, no code emitted.
    void jump(uint64_t target) {
        c->rec_end_vaddr = target;
    }

    // Indirect jump (JALR class): the interpreter's exact semantics, target
    // computed before the link write (rd may alias rs1) into a scratch slot
    // that the dynamic terminal deposits and looks up. Ends the trace.
    int dynamic_slot = -1;
    void jalr(uint8_t rd, uint8_t rs1, uint64_t imm, uint8_t size) {
        const int s1 = alloc_src(rs1);
        const int t = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        emit1(cp_li_table[t], imm);
        emit1(cp_add_table[t][t][s1]);
        const int m = alloc_scratch();
        if (c->rec_failed) {
            return;
        }
        emit1(cp_li_table[m], ~static_cast<uint64_t>(1));
        emit1(cp_and_table[t][t][m]);
        free_scratch(m);
        if (rd != 0) {
            li(rd, pc + size);
        }
        dynamic_slot = t;
    }

    void end() {
        c->rec_failed = true; // uncompilable: caller finishes before this insn
    }
};

enum class cp_fusion_op : uint8_t { none, slli, c_slli, srli, srli_full, srliw, c_add, c_lw, lbu, bne, auipc, addi };
enum class cp_fusion_match : uint8_t {
    slli_add,
    srliw_slli,
    slli_srli,
    zext32_add,
    shift_extract_add,
    scaled_lw,
    lbu_bne,
    auipc_addi
};
enum class cp_fusion_emit : uint8_t {
    slli_add,
    reg2,
    repartition_srliw_slli_add,
    zext32_add,
    shift_extract_add,
    scaled_lw,
    lbu_bne,
    constant
};

using cp_fusion_table2 = const cp_stencil_t *const (*)[CP_NSLOTS];
using cp_fusion_table3 = const cp_stencil_t *const (*)[CP_NSLOTS][CP_NSLOTS];

struct cp_fusion_variant {
    uint8_t imm0;
    uint8_t imm1;
    cp_fusion_table2 table2;
    cp_fusion_table3 table3;
};

struct cp_fusion_terminal {
    const char *name;
    cp_fusion_match match;
    cp_fusion_emit emit;
    uint8_t length;
    const cp_fusion_variant *variants;
    uint8_t nvariants;
};

struct cp_fusion_trie_edge {
    uint8_t from;
    cp_fusion_op op;
    uint8_t to;
};

struct cp_fusion_trie_node {
    int8_t terminal;
};

struct cp_fusion_config {
    const cp_fusion_trie_edge *edges;
    uint8_t nedges;
    const cp_fusion_trie_node *nodes;
    const cp_fusion_terminal *terminals;
    uint8_t nterminals;
};

// Reverse trie: matching begins at the newly emitted instruction and walks
// backward over the flattened guest instructions represented by the current
// emitted things. Host configuration selects terminals and stencil families;
// the walk, validation, rewind, and replacement mechanism is shared.
#if defined(__aarch64__)
static constexpr cp_fusion_variant cp_fusion_slli_add_variants[] = {
    {1, 0, cp_slli_add_sh1_table, nullptr},
    {2, 0, cp_slli_add_sh2_table, nullptr},
    {3, 0, cp_slli_add_sh3_table, nullptr},
};
static constexpr cp_fusion_variant cp_fusion_srliw_slli_variants[] = {
    {5, 2, cp_srliw5_slli2_table, nullptr},
};
static constexpr cp_fusion_variant cp_fusion_repartition_variants[] = {
    {5, 2, cp_slli_add_sh2_table, nullptr},
};
static constexpr cp_fusion_variant cp_fusion_slli_srli_variants[] = {
    {10, 20, cp_slli10_srli20_table, nullptr},
    {32, 32, cp_slli32_srli32_table, nullptr},
};
static constexpr cp_fusion_variant cp_fusion_zext32_add_variants[] = {
    {32, 32, nullptr, cp_slli32_srli32_add_table},
};
static constexpr cp_fusion_variant cp_fusion_shift_extract_add_variants[] = {
    {32, 31, nullptr, cp_slli32_srli31_add_table},
};
static constexpr cp_fusion_variant cp_fusion_scaled_lw_variants[] = {
    {2, 0, nullptr, cp_lw_slli2_add_table},
};
static constexpr cp_fusion_variant cp_fusion_no_variants[] = {{0, 0, nullptr, nullptr}};
static constexpr cp_fusion_terminal cp_fusion_terminals[] = {
    {"slli-add", cp_fusion_match::slli_add, cp_fusion_emit::slli_add, 2, cp_fusion_slli_add_variants, 3},
    {"srliw-slli-add", cp_fusion_match::srliw_slli, cp_fusion_emit::repartition_srliw_slli_add, 3,
        cp_fusion_repartition_variants, 1},
    {"srliw-slli", cp_fusion_match::srliw_slli, cp_fusion_emit::reg2, 2, cp_fusion_srliw_slli_variants, 1},
    {"slli-srli", cp_fusion_match::slli_srli, cp_fusion_emit::reg2, 2, cp_fusion_slli_srli_variants, 2},
    {"auipc-addi", cp_fusion_match::auipc_addi, cp_fusion_emit::constant, 2, cp_fusion_no_variants, 1},
    {"zext32-add", cp_fusion_match::zext32_add, cp_fusion_emit::zext32_add, 3,
        cp_fusion_zext32_add_variants, 1},
    {"shift-extract-add", cp_fusion_match::shift_extract_add, cp_fusion_emit::shift_extract_add, 3,
        cp_fusion_shift_extract_add_variants, 1},
    {"scaled-lw", cp_fusion_match::scaled_lw, cp_fusion_emit::scaled_lw, 3, cp_fusion_scaled_lw_variants, 1},
    {"lbu-bne", cp_fusion_match::lbu_bne, cp_fusion_emit::lbu_bne, 2, cp_fusion_no_variants, 1},
};
static constexpr cp_fusion_trie_edge cp_fusion_edges[] = {
    {0, cp_fusion_op::c_add, 1},
    {1, cp_fusion_op::c_slli, 2},
    {2, cp_fusion_op::srliw, 3},
    {0, cp_fusion_op::c_slli, 4},
    {4, cp_fusion_op::srliw, 5},
    {0, cp_fusion_op::srli, 6},
    {6, cp_fusion_op::slli, 7},
    {0, cp_fusion_op::addi, 8},
    {8, cp_fusion_op::auipc, 9},
    {1, cp_fusion_op::srli, 10},
    {10, cp_fusion_op::slli, 11},
    {1, cp_fusion_op::srli_full, 12},
    {12, cp_fusion_op::slli, 13},
    {0, cp_fusion_op::c_lw, 14},
    {14, cp_fusion_op::c_add, 15},
    {15, cp_fusion_op::c_slli, 16},
    {0, cp_fusion_op::bne, 17},
    {17, cp_fusion_op::lbu, 18},
};
static constexpr cp_fusion_trie_node cp_fusion_nodes[] = {
    {-1}, {-1}, {0}, {1}, {-1}, {2}, {-1}, {3}, {-1}, {4}, {-1}, {5}, {-1}, {6}, {-1}, {-1}, {7}, {-1}, {8},
};
static constexpr cp_fusion_config cp_fusion_host_config = {
    cp_fusion_edges, 18, cp_fusion_nodes, cp_fusion_terminals, 9};
#elif defined(__x86_64__)
static constexpr cp_fusion_variant cp_fusion_srliw_slli_variants[] = {
    {5, 2, cp_srliw5_slli2_table, nullptr},
};
static constexpr cp_fusion_variant cp_fusion_zext32_add_variants[] = {
    {32, 32, nullptr, cp_slli32_srli32_add_table},
};
static constexpr cp_fusion_variant cp_fusion_shift_extract_add_variants[] = {
    {32, 31, nullptr, cp_slli32_srli31_add_table},
};
static constexpr cp_fusion_variant cp_fusion_scaled_lw_variants[] = {
    {2, 0, nullptr, cp_lw_slli2_add_table},
};
static constexpr cp_fusion_variant cp_fusion_no_variants[] = {{0, 0, nullptr, nullptr}};
static constexpr cp_fusion_terminal cp_fusion_terminals[] = {
    {"srliw-slli", cp_fusion_match::srliw_slli, cp_fusion_emit::reg2, 2, cp_fusion_srliw_slli_variants, 1},
    {"auipc-addi", cp_fusion_match::auipc_addi, cp_fusion_emit::constant, 2, cp_fusion_no_variants, 1},
    {"zext32-add", cp_fusion_match::zext32_add, cp_fusion_emit::zext32_add, 3,
        cp_fusion_zext32_add_variants, 1},
    {"shift-extract-add", cp_fusion_match::shift_extract_add, cp_fusion_emit::shift_extract_add, 3,
        cp_fusion_shift_extract_add_variants, 1},
    {"scaled-lw", cp_fusion_match::scaled_lw, cp_fusion_emit::scaled_lw, 3, cp_fusion_scaled_lw_variants, 1},
    {"lbu-bne", cp_fusion_match::lbu_bne, cp_fusion_emit::lbu_bne, 2, cp_fusion_no_variants, 1},
};
static constexpr cp_fusion_trie_edge cp_fusion_edges[] = {
    {0, cp_fusion_op::c_slli, 1},
    {1, cp_fusion_op::srliw, 2},
    {0, cp_fusion_op::addi, 3},
    {3, cp_fusion_op::auipc, 4},
    {0, cp_fusion_op::c_add, 5},
    {5, cp_fusion_op::srli, 6},
    {6, cp_fusion_op::slli, 7},
    {5, cp_fusion_op::srli_full, 8},
    {8, cp_fusion_op::slli, 9},
    {0, cp_fusion_op::c_lw, 10},
    {10, cp_fusion_op::c_add, 11},
    {11, cp_fusion_op::c_slli, 12},
    {0, cp_fusion_op::bne, 13},
    {13, cp_fusion_op::lbu, 14},
};
static constexpr cp_fusion_trie_node cp_fusion_nodes[] = {
    {-1}, {-1}, {0}, {-1}, {1}, {-1}, {-1}, {2}, {-1}, {3}, {-1}, {-1}, {4}, {-1}, {5},
};
static constexpr cp_fusion_config cp_fusion_host_config = {
    cp_fusion_edges, 14, cp_fusion_nodes, cp_fusion_terminals, 6};
#else
static constexpr cp_fusion_config cp_fusion_host_config = {nullptr, 0, nullptr, nullptr, 0};
#endif

static FORCE_INLINE cp_fusion_op cp_fusion_class(uint16_t label, uint32_t insn) {
    switch (static_cast<tc_label>(label)) {
        case tc_label::C_SLLI:
            return cp_fusion_op::c_slli;
        case tc_label::SLLI_rdN:
            return cp_fusion_op::slli;
        case tc_label::C_SRLI:
            return cp_fusion_op::srli;
        case tc_label::SRLI_SRAI_rdN:
            return ((insn >> 30) & 1) == 0 ? cp_fusion_op::srli_full : cp_fusion_op::none;
        case tc_label::SRLIW_SRAIW_rdN:
            return ((insn >> 30) & 1) == 0 ? cp_fusion_op::srliw : cp_fusion_op::none;
        case tc_label::C_ADD:
            return cp_fusion_op::c_add;
        case tc_label::C_LW:
            return cp_fusion_op::c_lw;
        case tc_label::LBU_rdN:
            return cp_fusion_op::lbu;
        case tc_label::BNE:
            return cp_fusion_op::bne;
        case tc_label::AUIPC_rdN:
            return cp_fusion_op::auipc;
        case tc_label::ADDI_rdN:
            return cp_fusion_op::addi;
        default:
            return cp_fusion_op::none;
    }
}

static FORCE_INLINE uint8_t cp_fusion_trie_next(uint8_t node, cp_fusion_op op) {
    for (uint8_t i = 0; i < cp_fusion_host_config.nedges; ++i) {
        const auto &edge = cp_fusion_host_config.edges[i];
        if (edge.from == node && edge.op == op) {
            return edge.to;
        }
    }
    return UINT8_MAX;
}

static bool cp_fusion_consecutive(const cp_state::cp_fusion_insn *seq, uint16_t count) {
    for (uint16_t i = 1; i < count; ++i) {
        const uint8_t size = cp_label_size[seq[i - 1].label];
        if (seq[i].vpc != seq[i - 1].vpc + size) {
            return false;
        }
    }
    return true;
}

static const cp_fusion_variant *cp_fusion_terminal_variant(
    const cp_fusion_terminal &terminal, const cp_state::cp_fusion_insn *seq) {
    if (!cp_fusion_consecutive(seq, terminal.length)) {
        return nullptr;
    }
    uint32_t imm0 = 0;
    uint32_t imm1 = 0;
    switch (terminal.match) {
        case cp_fusion_match::slli_add:
            if (insn_get_rd(seq[0].insn) != insn_get_rd(seq[1].insn)) {
                return nullptr;
            }
            imm0 = insn_get_CI_CB_imm(seq[0].insn);
            break;
        case cp_fusion_match::srliw_slli:
            if ((seq[0].insn >> 30) != 0 || insn_get_rd(seq[0].insn) != insn_get_rd(seq[1].insn)) {
                return nullptr;
            }
            if (terminal.length == 3 && insn_get_rd(seq[1].insn) != insn_get_rd(seq[2].insn)) {
                return nullptr;
            }
            imm0 = static_cast<uint32_t>(insn_I_get_imm(seq[0].insn));
            imm1 = insn_get_CI_CB_imm(seq[1].insn);
            break;
        case cp_fusion_match::slli_srli:
            if (insn_get_rd(seq[0].insn) != insn_get_CL_CS_CA_CB_rs1(seq[1].insn)) {
                return nullptr;
            }
            imm0 = static_cast<uint32_t>(insn_I_get_imm(seq[0].insn));
            imm1 = insn_get_CI_CB_imm(seq[1].insn);
            break;
        case cp_fusion_match::zext32_add: {
            const uint32_t rd = insn_get_rd(seq[0].insn);
            const uint32_t rs1 = insn_get_rs1(seq[0].insn);
            const uint32_t rs2 = insn_get_CR_CSS_rs2(seq[2].insn);
            if (rd != insn_get_CL_CS_CA_CB_rs1(seq[1].insn) || rd != insn_get_rd(seq[2].insn) || rd == rs1 ||
                rd == rs2 || rs1 == rs2) {
                return nullptr;
            }
            imm0 = static_cast<uint32_t>(insn_I_get_imm(seq[0].insn));
            imm1 = insn_get_CI_CB_imm(seq[1].insn);
            break;
        }
        case cp_fusion_match::shift_extract_add:
            if (insn_get_rd(seq[0].insn) != insn_get_rs1(seq[1].insn) ||
                insn_get_rd(seq[1].insn) != insn_get_rs1(seq[0].insn) ||
                insn_get_rd(seq[1].insn) != insn_get_rd(seq[2].insn) ||
                insn_get_rd(seq[0].insn) == insn_get_rd(seq[1].insn) ||
                insn_get_rd(seq[0].insn) == insn_get_CR_CSS_rs2(seq[2].insn) ||
                insn_get_rd(seq[1].insn) == insn_get_CR_CSS_rs2(seq[2].insn)) {
                return nullptr;
            }
            imm0 = static_cast<uint32_t>(insn_I_get_imm(seq[0].insn));
            imm1 = static_cast<uint32_t>(insn_I_get_imm(seq[1].insn));
            break;
        case cp_fusion_match::scaled_lw: {
            const uint32_t address_rd = insn_get_rd(seq[0].insn);
            const uint32_t add_rs = insn_get_CR_CSS_rs2(seq[1].insn);
            const uint32_t load_rd = insn_get_CIW_CL_rd_CS_CA_rs2(seq[2].insn);
            if (address_rd != insn_get_rd(seq[1].insn) ||
                address_rd != insn_get_CL_CS_CA_CB_rs1(seq[2].insn) || address_rd == add_rs || load_rd == add_rs) {
                return nullptr;
            }
            imm0 = insn_get_CI_CB_imm(seq[0].insn);
            imm1 = static_cast<uint32_t>(insn_get_C_LW_C_SW_imm(seq[2].insn));
            break;
        }
        case cp_fusion_match::lbu_bne: {
            const uint32_t rd = insn_get_rd(seq[0].insn);
            const uint32_t base = insn_get_rs1(seq[0].insn);
            const uint32_t branch_rs1 = insn_get_rs1(seq[1].insn);
            const uint32_t branch_rs2 = insn_get_rs2(seq[1].insn);
            const uint32_t compare = rd == branch_rs1 ? branch_rs2 : (rd == branch_rs2 ? branch_rs1 : 0);
            if (rd == 0 || compare == 0 || rd == base || rd == compare || base == compare) {
                return nullptr;
            }
            return &terminal.variants[0];
        }
        case cp_fusion_match::auipc_addi: {
            const uint32_t rd = insn_get_rd(seq[0].insn);
            if (rd == 0 || rd != insn_get_rd(seq[1].insn) || rd != insn_get_rs1(seq[1].insn)) {
                return nullptr;
            }
            return &terminal.variants[0];
        }
    }
    for (uint8_t i = 0; i < terminal.nvariants; ++i) {
        if (terminal.variants[i].imm0 == imm0 && terminal.variants[i].imm1 == imm1) {
            return &terminal.variants[i];
        }
    }
    return nullptr;
}

static uint8_t cp_fusion_emit_replacement(cp_state *c, const cp_fusion_terminal &terminal,
    const cp_fusion_variant &variant, const cp_state::cp_fusion_insn *seq, uint16_t first,
    const cp_state::cp_form_checkpoint &start, cp_state::cp_fusion_thing *things) {
    cp_former f{c, seq[0].vpc};
    switch (terminal.emit) {
        case cp_fusion_emit::slli_add:
            f.fused_slli_add(variant.table2, insn_get_rd(seq[0].insn), insn_get_CR_CSS_rs2(seq[1].insn));
            things[0] = {start, first, 2};
            return 1;
        case cp_fusion_emit::reg2:
            f.fused_reg2(variant.table2, insn_get_rd(seq[0].insn), insn_get_rs1(seq[0].insn));
            things[0] = {start, first, 2};
            return 1;
        case cp_fusion_emit::repartition_srliw_slli_add: {
            f.reg2i(cp_srlw_table, insn_get_rd(seq[0].insn), insn_get_rs1(seq[0].insn), variant.imm0);
            cp_state::cp_form_checkpoint middle{};
            cp_save_checkpoint(c, middle);
            f.pc = seq[1].vpc;
            f.fused_slli_add(variant.table2, insn_get_rd(seq[1].insn), insn_get_CR_CSS_rs2(seq[2].insn));
            things[0] = {start, first, 1};
            things[1] = {middle, static_cast<uint16_t>(first + 1), 2};
            return 2;
        }
        case cp_fusion_emit::zext32_add:
            f.fused_zext32_add(variant.table3, insn_get_rd(seq[0].insn), insn_get_rs1(seq[0].insn),
                insn_get_CR_CSS_rs2(seq[2].insn));
            things[0] = {start, first, 3};
            return 1;
        case cp_fusion_emit::shift_extract_add:
            f.fused_shift_extract_add(variant.table3, insn_get_rd(seq[0].insn), insn_get_rd(seq[1].insn),
                insn_get_CR_CSS_rs2(seq[2].insn));
            things[0] = {start, first, 3};
            return 1;
        case cp_fusion_emit::scaled_lw:
            f.pc = seq[2].vpc;
            f.fused_scaled_lw(variant.table3, insn_get_rd(seq[0].insn), insn_get_CR_CSS_rs2(seq[1].insn),
                insn_get_CIW_CL_rd_CS_CA_rs2(seq[2].insn));
            things[0] = {start, first, 3};
            return 1;
        case cp_fusion_emit::lbu_bne:
            c->rec_failed = true; // emitted only after the recorded direction resolves
            return 0;
        case cp_fusion_emit::constant:
            f.li(insn_get_rd(seq[0].insn), seq[0].vpc + static_cast<uint64_t>(insn_U_get_imm(seq[0].insn)) +
                    static_cast<uint64_t>(insn_I_get_imm(seq[1].insn)));
            things[0] = {start, first, 2};
            return 1;
    }
    c->rec_failed = true;
    return 0;
}

static void cp_fusion_record(cp_state *c, uint64_t vpc, uint32_t insn, tc_label label,
    const cp_state::cp_form_checkpoint &start) {
    if (c->fusion_ninsns >= cp_state::max_len || c->fusion_nthings >= cp_state::max_len) {
        return;
    }
    const uint16_t current = c->fusion_ninsns++;
    c->fusion_insns[current] = {vpc, insn, static_cast<uint16_t>(label)};
    c->fusion_things[c->fusion_nthings++] = {start, current, 1};

    uint8_t node = 0;
    int8_t best = -1;
    const cp_fusion_variant *best_variant = nullptr;
    uint16_t best_first = current;
    uint16_t best_len = 0;
    const uint16_t max_walk = std::min<uint16_t>(c->fusion_ninsns, cp_state::max_fusion_len);
    for (uint16_t depth = 0; depth < max_walk; ++depth) {
        const uint16_t at = static_cast<uint16_t>(current - depth);
        node = cp_fusion_trie_next(
            node, cp_fusion_class(c->fusion_insns[at].label, c->fusion_insns[at].insn));
        if (node == UINT8_MAX) {
            break;
        }
        const int8_t terminal_index = cp_fusion_host_config.nodes[node].terminal;
        if (terminal_index >= 0) {
            const auto &terminal = cp_fusion_host_config.terminals[terminal_index];
            const auto *variant = cp_fusion_terminal_variant(terminal, &c->fusion_insns[at]);
            if (variant == nullptr) {
                continue;
            }
            best = terminal_index;
            best_variant = variant;
            best_first = at;
            best_len = depth + 1;
        }
    }
    if (best < 0) {
        return;
    }
    if (cp_fusion_host_config.terminals[best].emit == cp_fusion_emit::lbu_bne) {
        return; // branch direction is known on the next record call
    }

    uint16_t first_thing = c->fusion_nthings;
    while (first_thing > 0 && c->fusion_things[first_thing - 1].first >= best_first) {
        --first_thing;
    }
    if (first_thing >= c->fusion_nthings || c->fusion_things[first_thing].first != best_first) {
        return; // the longest terminal begins inside an already fused thing
    }
    const auto checkpoint = c->fusion_things[first_thing].start;
    const uint64_t old_bytes = c->heap.curr - checkpoint.heap_curr;
    cp_restore_checkpoint(c, checkpoint);
    cp_state::cp_fusion_thing replacement[2]{};
    const uint8_t nreplacement = cp_fusion_emit_replacement(c, cp_fusion_host_config.terminals[best], *best_variant,
        &c->fusion_insns[best_first], best_first, checkpoint, replacement);
    if (c->rec_failed) {
        return;
    }
    const uint64_t new_bytes = c->heap.curr - checkpoint.heap_curr;
    c->fusion_nthings = first_thing;
    for (uint8_t i = 0; i < nreplacement; ++i) {
        c->fusion_things[c->fusion_nthings++] = replacement[i];
    }
    ++c->fusion_rewrites;
    c->fusion_guest_insns += best_len;
    c->fusion_old_bytes += old_bytes;
    c->fusion_new_bytes += new_bytes;
    ++c->fusion_terminals[best];
}

static bool cp_fusion_resolve_lbu_bne(cp_state *c, uint64_t successor) {
    static const bool disabled = std::getenv("CP_FUSION_LBU_BNE_DISABLE") != nullptr;
    if (disabled) {
        return false;
    }
    if (c->fusion_ninsns < 2 || c->rec_len == 0) {
        return false;
    }
    int8_t terminal_index = -1;
    for (uint8_t i = 0; i < cp_fusion_host_config.nterminals; ++i) {
        if (cp_fusion_host_config.terminals[i].emit == cp_fusion_emit::lbu_bne) {
            terminal_index = static_cast<int8_t>(i);
            break;
        }
    }
    if (terminal_index < 0) {
        return false;
    }
    const uint16_t first = static_cast<uint16_t>(c->fusion_ninsns - 2);
    const auto &terminal = cp_fusion_host_config.terminals[terminal_index];
    const auto *seq = &c->fusion_insns[first];
    if (cp_fusion_class(seq[0].label, seq[0].insn) != cp_fusion_op::lbu ||
        cp_fusion_class(seq[1].label, seq[1].insn) != cp_fusion_op::bne) {
        return false;
    }
    if (cp_fusion_terminal_variant(terminal, seq) == nullptr) {
        return false;
    }
    const uint64_t taken = c->pb_taken_target;
    const uint64_t fall = c->pb_vaddr + c->pb_size;
    if (successor != taken && successor != fall) {
        return false;
    }

    uint16_t first_thing = c->fusion_nthings;
    while (first_thing > 0 && c->fusion_things[first_thing - 1].first >= first) {
        --first_thing;
    }
    if (first_thing >= c->fusion_nthings || c->fusion_things[first_thing].first != first) {
        return false;
    }
    const auto checkpoint = c->fusion_things[first_thing].start;
    const uint64_t old_bytes = c->heap.curr - checkpoint.heap_curr;
    cp_restore_checkpoint(c, checkpoint);

    const uint32_t rd = insn_get_rd(seq[0].insn);
    const uint32_t branch_rs1 = insn_get_rs1(seq[1].insn);
    const uint32_t branch_rs2 = insn_get_rs2(seq[1].insn);
    const uint32_t compare = rd == branch_rs1 ? branch_rs2 : branch_rs1;
    const bool hot_taken = successor == taken;
    const auto table = hot_taken ? cp_lbu_bnet_table : cp_lbu_bnef_table;
    cp_former f{c, seq[0].vpc};
    f.fused_lbu_bne(table, static_cast<uint8_t>(rd), static_cast<uint8_t>(insn_get_rs1(seq[0].insn)),
        static_cast<uint64_t>(insn_I_get_imm(seq[0].insn)), static_cast<uint8_t>(compare), c->rec_len - 1,
        static_cast<int64_t>((hot_taken ? fall : taken) - c->rec_head), c->rec_len + 1);
    if (c->rec_failed) {
        return true;
    }

    const uint64_t new_bytes = c->heap.curr - checkpoint.heap_curr;
    c->fusion_nthings = first_thing;
    c->fusion_things[c->fusion_nthings++] = {checkpoint, first, 2};
    ++c->fusion_rewrites;
    c->fusion_guest_insns += 2;
    c->fusion_old_bytes += old_bytes;
    c->fusion_new_bytes += new_bytes;
    ++c->fusion_terminals[terminal_index];
    return true;
}

static void cp_fusion_print_terminal_stats(const cp_state *c) {
    std::fprintf(stderr, "cp: fusion terminals");
    for (uint8_t i = 0; i < cp_fusion_host_config.nterminals; ++i) {
        std::fprintf(stderr, " %s %llu", cp_fusion_host_config.terminals[i].name,
            static_cast<unsigned long long>(c->fusion_terminals[i]));
    }
    std::fputc('\n', stderr);
}

// Debug switch: refuse trace entries past a budget, so a divergence can be
// bisected to the exact entry without changing what gets recorded (the
// lightning TC_LIGHTNING_MAX_ENTER device). Compiled cheaply: one load and
// compare per entry attempt, off by default (budget < 0 means unlimited).
static int64_t cp_enter_budget() {
    static const int64_t budget = [] {
        const char *s = std::getenv("CP_MAX_ENTER");
        return s == nullptr ? INT64_C(-1) : std::strtoll(s, nullptr, 0);
    }();
    return budget;
}

static FORCE_INLINE bool cp_enter_allowed(cp_state *c) {
    const int64_t budget = cp_enter_budget();
    if (budget < 0) {
        return true;
    }
    if (static_cast<int64_t>(c->entries + c->continue_enters) >= budget) {
        return false;
    }
    return true;
}

// CP_PROBE=N: dump the guest register file at entry attempts N and N+1
// (attempts count both allowed and refused entries), so a bisected entry's
// architectural effect can be compared against its interpretation.
static int64_t cp_probe_at() {
    static const int64_t at = [] {
        const char *s = std::getenv("CP_PROBE");
        return s == nullptr ? INT64_C(-1) : std::strtoll(s, nullptr, 0);
    }();
    return at;
}

static void cp_probe(cp_state *c, const penumbra_state *penumbra, uint64_t vpc) {
    static int64_t attempts = 0;
    const int64_t at = cp_probe_at();
    if (at < 0) {
        return;
    }
    ++attempts;
    const int64_t done = static_cast<int64_t>(c->entries + c->continue_enters);
    if (done >= at - 2 && done <= at + 1) {
        const auto *state =
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const processor_state *>(
                reinterpret_cast<const unsigned char *>(penumbra) - offsetof(processor_state, penumbra));
        std::fprintf(stderr, "cp-probe attempt=%lld entries=%lld vpc=%llx", static_cast<long long>(attempts),
            static_cast<long long>(done), static_cast<unsigned long long>(vpc));
        for (int i = 1; i < 32; ++i) {
            std::fprintf(stderr, " %llx", static_cast<unsigned long long>(state->shadow.registers.x[i]));
        }
        std::fprintf(stderr, "\n");
    }
}

// ---------------------------------------------------------------------------
// Recording driver.

template <typename STATE_ACCESS>
static void cp_abort(tc_context<STATE_ACCESS> *tcc) {
    cp_state *c = tcc->cp;
    if (!c->recording) {
        return;
    }
    c->heap.curr = static_cast<size_t>(c->rec_alloc_start);
    c->recording = false;
    cp_heap_protect_flush(&c->heap);
}

// Emits the stores for a dirty-slot snapshot under the slot-to-guest
// mapping that was current when the snapshot was taken (eviction remaps
// slots mid-trace).
static void cp_emit_stores(cp_state *c, uint32_t dirty, const uint8_t (&slot_guest)[cp_state::nslots]) {
    for (uint32_t slot = 0; slot < cp_state::nslots; ++slot) {
        if ((dirty & (1u << slot)) != 0 && slot_guest[slot] != 0xff && slot_guest[slot] != 0) {
            const uint64_t imm[2] = {0, 0};
            uint8_t *cont[2] = {nullptr, nullptr};
            if (cp_emit(&c->heap, cp_gxs_table[slot][slot_guest[slot] - 1], imm, cont) == nullptr) {
                c->rec_failed = true;
            }
        }
    }
}

// Emits one exit: stores, relative exit stub, far jump to the island (or a
// direct branch to `target` when given, for the cyclic back edge). For the
// straight terminal, link_site receives the stub's trailing branch, the one
// site the pending-link pass may later retarget to a successor's entry.
static uint8_t *cp_emit_exit(cp_state *c, uint32_t dirty, const uint8_t (&slot_guest)[cp_state::nslots], int64_t delta,
    uint32_t pending, uint8_t *target = nullptr, cp_trace *link_out = nullptr, const void *island = nullptr) {
    uint8_t *at = c->heap.base + c->heap.curr;
    cp_emit_stores(c, dirty, slot_guest);
    uint8_t *stub = c->heap.base + c->heap.curr;
    const uint64_t imm[2] = {static_cast<uint64_t>(delta), pending};
    if (island == nullptr) {
        island = c->continue_island;
    }
    uint8_t *cont[2] = {target != nullptr ? target : const_cast<uint8_t *>(static_cast<const uint8_t *>(island)),
        nullptr};
    if (cp_emit(&c->heap, &cp_s_cp_exit_stub, imm, cont) == nullptr) {
        c->rec_failed = true;
        return at;
    }
    if (link_out != nullptr) {
        const cp_stencil_t *st = &cp_s_cp_exit_stub;
        for (uint16_t i = 0; i < st->npatches; ++i) {
            const cp_patch_t *p = &st->patches[i];
            if ((p->kind == CP_P_JUMP26 || p->kind == CP_P_JMPREL32) && p->ordinal == 0) {
                link_out->link_site = static_cast<uint32_t>((stub + p->offset) - c->heap.base);
                link_out->link_kind = p->kind;
                link_out->link_addend = p->addend;
            }
        }
    }
    return at;
}

// Emits a probing exit: stores, countdown charge, the static successor vpc
// into slot 0, and the front-cache probe, chaining a hit into the target's
// self-validating entry and leaving for the (counting) island on miss. The
// slots are dead after the stores, so slot 0 is free to clobber. This is
// RVVM's block-end lookup: exits reach the interpreter only on real misses.
static void cp_emit_probe_exit(cp_state *c, uint32_t dirty, const uint8_t (&slot_guest)[cp_state::nslots],
    int64_t delta, uint32_t pending, uint64_t target_vpc, const void *miss_island) {
    cp_emit_stores(c, dirty, slot_guest);
    uint8_t *fall[2] = {nullptr, nullptr};
    const uint64_t imm_stub[2] = {static_cast<uint64_t>(delta), pending};
    const uint64_t imm_li[2] = {target_vpc, 0};
    const uint64_t imm_lu[2] = {
        reinterpret_cast<uint64_t>(&c->front[cp_front_context(c->rec_ctx_slot_base)][0]), 0};
    uint8_t *miss[2] = {const_cast<uint8_t *>(static_cast<const uint8_t *>(miss_island)), nullptr};
    if (cp_emit(&c->heap, &cp_s_cp_exit_stub, imm_stub, fall) == nullptr ||
        cp_emit(&c->heap, cp_li_table[0], imm_li, fall) == nullptr ||
        cp_emit(&c->heap, cp_lookup_table[0], imm_lu, miss) == nullptr) {
        c->rec_failed = true;
    }
}

// Re-patches the value holes of an already-emitted stencil instance.
static void cp_repatch_imm(uint8_t *dst, const cp_stencil_t *st, uint8_t ordinal, uint64_t value) {
    for (uint16_t i = 0; i < st->npatches; ++i) {
        const cp_patch_t *p = &st->patches[i];
        if (p->ordinal != ordinal || p->kind == CP_P_JUMP26 || p->kind == CP_P_JMPREL32) {
            continue;
        }
        uint8_t *site = dst + p->offset;
        if (p->kind == CP_P_ABS64) {
            const uint64_t v = value + static_cast<uint64_t>(p->addend);
            std::memcpy(site, &v, 8);
        } else if (p->kind == CP_P_ABS32) {
            const uint32_t v = static_cast<uint32_t>(value + static_cast<uint64_t>(p->addend));
            std::memcpy(site, &v, 4);
        } else if (p->kind == CP_P_U12) {
            const uint32_t negative = static_cast<uint32_t>(value >> 63);
            const uint32_t magnitude = static_cast<uint32_t>(negative != 0 ? (~value + 1u) : value);
            uint32_t insn = 0;
            std::memcpy(&insn, site, 4);
            insn = (insn & ~((1u << 30) | (0xfffu << 10))) | (negative << 30) | ((magnitude & 0xfffu) << 10);
            std::memcpy(site, &insn, 4);
        } else if (p->kind == CP_P_SELECT8) {
            const uint32_t choices = static_cast<uint32_t>(p->addend);
            *site = static_cast<uint8_t>(choices >> (8u * static_cast<uint32_t>(value)));
        } else {
            const unsigned shift = 16u * static_cast<unsigned>(p->kind - CP_P_G0);
            const uint32_t field = static_cast<uint32_t>(value >> shift) & 0xffffu;
            uint32_t insn = 0;
            std::memcpy(&insn, site, 4);
            if (insn == 0xd503201fu) {
                // Compacted movk. Repatched holes carry only values below
                // 2^16 (the tick guard's pending count), so a compacted
                // upper field never needs to become nonzero again.
                continue;
            }
            insn = (insn & ~(0xffffu << 5)) | (field << 5);
            std::memcpy(site, &insn, 4);
        }
    }
}

template <typename STATE_ACCESS>
static void cp_finish(tc_context<STATE_ACCESS> *tcc, bool cyclic, int dynamic_slot = -1) {
    cp_state *c = tcc->cp;
    c->recording = false;
    if (c->rec_failed || c->rec_len == 0) {
        c->heap.curr = static_cast<size_t>(c->rec_alloc_start);
        if (c->rec_len == 0 && !c->rec_failed) {
            cp_insert(c, c->rec_head, cp_state::interpreted_marker);
            ++c->empty_marked;
        }
        cp_heap_protect_flush(&c->heap);
        return;
    }
    if (c->ntraces >= cp_state::max_traces) {
        c->heap.curr = static_cast<size_t>(c->rec_alloc_start);
        cp_heap_protect_flush(&c->heap);
        cp_flush(c);
        return;
    }

    cp_trace &t = c->pool[c->ntraces];
    t.link_site = 0;
    t.link_kind = 0;
    t.link_addend = 0;
    t.link_target = cp_state::none_link;
    t.successor = c->rec_end_vaddr;

    // Terminal: cyclic traces store and loop to their own entry; dynamic
    // (JALR-class) traces charge the countdown, deposit the target as the
    // interpreter would, and probe the front cache, chaining into a hit's
    // self-validating entry or leaving for the island; straight traces
    // store and leave for the successor.
    auto *const penumbra_fin =
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<penumbra_state *>(reinterpret_cast<unsigned char *>(tcc) - offsetof(penumbra_state, scratch));
    static const bool no_carry = std::getenv("CP_NO_CARRY") != nullptr; // A/B measurement switch
    if (cyclic && c->rec_carry_ok && !no_carry) {
        // Loop-carried replay: discard the first-pass tick and body, re-emit
        // with every first-use load hoisted into a preheader (plus fresh
        // loads for write-only registers, so every guest-bound slot holds
        // its architectural value at the tick), the tick guard after the
        // preheader, and a back edge that only charges the countdown and
        // re-checks the tick. The slot registers carry across iterations in
        // the pinned contract; publishing to the register file moves to the
        // exit paths, which store the body's cumulative dirty set under the
        // (stable, by eligibility) final slot mapping.
        c->heap.curr = static_cast<size_t>(c->rec_body_start - c->heap.base);
        uint8_t *fall[2] = {nullptr, nullptr};
        c->rec_start = c->heap.base + c->heap.curr;
        bool had_load[cp_state::nslots] = {};
        for (uint32_t i = 0; i < c->rec_log_len; ++i) {
            const auto &r = c->rec_log[i];
            if (r.load_slot >= 0) {
                had_load[r.load_slot] = true;
                const uint64_t imm_l[2] = {r.imm0, r.imm1};
                if (cp_emit(&c->heap, r.st, imm_l, fall) == nullptr) {
                    c->rec_failed = true;
                }
            }
        }
        for (uint32_t slot = 0; slot < cp_state::nslots; ++slot) {
            if (!had_load[slot] && c->slot_guest[slot] != 0xff && c->slot_guest[slot] != 0) {
                const uint64_t imm_l[2] = {0, 0};
                if (cp_emit(&c->heap, cp_gxl_table[slot][c->slot_guest[slot] - 1], imm_l, fall) == nullptr) {
                    c->rec_failed = true;
                }
            }
        }
        const uint64_t imm_t[2] = {0, 0};
        uint8_t *tick_cont[2] = {nullptr, c->heap.base}; // placeholder, re-pointed below
        c->rec_tick_site = cp_emit(&c->heap, &cp_s_cp_tick_guard, imm_t, tick_cont);
        if (c->rec_tick_site == nullptr) {
            c->rec_failed = true;
        }
        for (uint32_t i = 0; i < c->rec_log_len && !c->rec_failed; ++i) {
            const auto &r = c->rec_log[i];
            if (r.load_slot >= 0) {
                continue;
            }
            const uint64_t imm_b[2] = {r.imm0, r.imm1};
            uint8_t *cont_b[3] = {nullptr, r.bail_index >= 0 ? c->heap.base : nullptr,
                r.bail_index2 >= 0 ? c->heap.base : nullptr};
            uint8_t *at = cp_emit(&c->heap, r.st, imm_b, cont_b);
            if (at == nullptr) {
                c->rec_failed = true;
                break;
            }
            if (r.bail_index >= 0) {
                const cp_patch_t *p = cp_bail_patch(r.st);
                cp_bail &b = c->bails[r.bail_index];
                b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
                b.guard_kind = p->kind;
                b.guard_addend = p->addend;
            }
            if (r.bail_index2 >= 0) {
                const cp_patch_t *p = cp_cont_patch(r.st, 2);
                cp_bail &b = c->bails[r.bail_index2];
                b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
                b.guard_kind = p->kind;
                b.guard_addend = p->addend;
            }
            if (r.resume_bail_index >= 0) {
                c->bails[r.resume_bail_index].fp_resume = static_cast<uint32_t>(c->heap.curr);
            }
        }
        // Back edge: charge the iteration, re-check the tick.
        const uint64_t imm_be[2] = {0, c->rec_len};
        uint8_t *cont_be[2] = {c->rec_tick_site, nullptr};
        if (cp_emit(&c->heap, &cp_s_cp_exit_stub, imm_be, cont_be) == nullptr) {
            c->rec_failed = true;
        }
        // The tick's bail publishes the cumulative dirty set before leaving.
        if (!c->rec_failed) {
            uint8_t *tick_bail = cp_emit_exit(c, c->reg_dirty, c->slot_guest, 0, 0, nullptr, nullptr, c->tick_island);
            const cp_patch_t *tp = cp_bail_patch(&cp_s_cp_tick_guard);
            cp_patch_branch(c->rec_tick_site + tp->offset, tp->kind, tp->addend, tick_bail);
        }
        // Every body bail publishes the cumulative set too: on iteration N a
        // bail must cover registers written after its position in pass N-1.
        for (uint32_t i = 0; i < c->nbails; ++i) {
            c->bails[i].dirty = c->reg_dirty;
            std::memcpy(c->bails[i].slot_guest, c->slot_guest, sizeof(c->bails[i].slot_guest));
        }
        ++c->carried;
    } else if (cyclic) {
        cp_emit_exit(c, c->reg_dirty, c->slot_guest, 0, c->rec_len, c->rec_start);
    } else if (dynamic_slot >= 0) {
        cp_emit_stores(c, c->reg_dirty, c->slot_guest);
        uint8_t *fall[2] = {nullptr, nullptr};
        uint8_t *isl[2] = {const_cast<uint8_t *>(static_cast<const uint8_t *>(c->miss_island)), nullptr};
        const uint64_t imm_stub[2] = {0, c->rec_len};
        const uint64_t imm_dep[2] = {reinterpret_cast<uint64_t>(&penumbra_fin->fetch_vf_offset), 0};
        const uint64_t imm_lu[2] = {
            reinterpret_cast<uint64_t>(&c->front[cp_front_context(c->rec_ctx_slot_base)][0]), 0};
        if (cp_emit(&c->heap, &cp_s_cp_exit_stub, imm_stub, fall) == nullptr ||
            cp_emit(&c->heap, cp_deposit_pc_table[dynamic_slot], imm_dep, fall) == nullptr ||
            cp_emit(&c->heap, cp_lookup_table[dynamic_slot], imm_lu, isl) == nullptr) {
            c->rec_failed = true;
        }
    } else if (tlb_addr_page(c->rec_end_vaddr) != tlb_addr_page(c->rec_head)) {
        // Cross-page successor: no pending-link site, probe the front cache
        // instead (the same-page case keeps the patchable direct link).
        cp_emit_probe_exit(c, c->reg_dirty, c->slot_guest, static_cast<int64_t>(c->rec_end_vaddr - c->rec_head),
            c->rec_len, c->rec_end_vaddr, c->terminal_island);
    } else {
        cp_emit_exit(c, c->reg_dirty, c->slot_guest, static_cast<int64_t>(c->rec_end_vaddr - c->rec_head), c->rec_len,
            nullptr, &t, c->terminal_island);
    }

    // Grouped bail blocks, then patch each guard's bail branch.
    for (uint32_t i = 0; i < c->nbails && !c->rec_failed; ++i) {
        const cp_bail &b = c->bails[i];
        uint8_t *block = c->heap.base + c->heap.curr;
        if (b.is_fp) {
            const uint64_t imm[4] = {reinterpret_cast<uint64_t>(&cp_fp_helper_soft), b.fp_insn, 0, 0};
            uint8_t *cont[2] = {c->heap.base + b.fp_resume, c->heap.base}; // failure target patched below
            uint8_t *call = cp_emit(&c->heap, &cp_s_cp_fp_soft, imm, cont);
            if (call == nullptr) {
                c->rec_failed = true;
                break;
            }
            uint8_t *failure =
                cp_emit_exit(c, b.dirty, b.slot_guest, b.delta, b.pending, nullptr, nullptr, c->continue_cold_island);
            const cp_patch_t *failure_patch = cp_bail_patch(&cp_s_cp_fp_soft);
            cp_patch_branch(call + failure_patch->offset, failure_patch->kind, failure_patch->addend, failure);
        } else if (b.is_cold) {
            cp_emit_exit(c, b.dirty, b.slot_guest, b.delta, b.pending, nullptr, nullptr, c->continue_cold_island);
        } else if (b.pending == 0) {
            // A bail that retired nothing must not chain or re-enter: only
            // the interpreter's slow path (the fill) makes progress.
            cp_emit_exit(c, b.dirty, b.slot_guest, b.delta, b.pending, nullptr, nullptr, c->mem_bail_cold_island);
        } else {
            cp_emit_probe_exit(c, b.dirty, b.slot_guest, b.delta, b.pending,
                c->rec_head + static_cast<uint64_t>(b.delta), b.is_branch ? c->branch_bail_island : c->mem_bail_island);
        }
        cp_patch_branch(c->heap.base + b.guard_site, b.guard_kind, b.guard_addend, block);
    }

    // The entry guard's pending count is the whole body.
    cp_repatch_imm(c->rec_tick_site, &cp_s_cp_tick_guard, 0, c->rec_len);

    if (c->rec_failed) {
        c->heap.curr = static_cast<size_t>(c->rec_alloc_start);
        cp_heap_protect_flush(&c->heap);
        return;
    }

    t.head = c->rec_head;
    t.code_vf_offset = c->rec_code_vf_offset;
    t.ctx_slot_base = c->rec_ctx_slot_base;
    t.code_start = c->heap.base + c->rec_alloc_start;
    t.code_size = static_cast<uint32_t>(c->heap.curr - static_cast<size_t>(c->rec_alloc_start));
    t.len = c->rec_len;
    t.nhpages = c->rec_nhpages;
    for (uint8_t j = 0; j < t.nhpages; ++j) {
        t.hpage[j] = c->rec_hpage[j];
        cp_insert_hpage(c, t.hpage[j]);
    }
    t.dead = false;
    t.carried = cyclic && c->rec_carry_ok;
    t.exec_count = 0;
    t.fn = c->rec_start;
    t.call_fn = c->rec_call_start;
    cp_front_put(c, t.ctx_slot_base, t.head, t.call_fn);
    ++c->ntraces;
    cp_insert(c, t.head, static_cast<uint16_t>(c->ntraces));
    ++c->installed;
    c->emitted_bytes += t.code_size;

    // Evict the trace's pages from the hot write-TLB set (hot side only; the
    // shadow is architectural). While a page sits in a hot write slot, stores
    // to it are silent; the next store re-verifies through the notifying
    // promotion, which is what makes stores to traced pages observable.
    auto *const penumbra =
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<penumbra_state *>(reinterpret_cast<unsigned char *>(tcc) - offsetof(penumbra_state, scratch));
    for (uint64_t slot = 0; slot < TLB_SET_SLOTS; ++slot) {
        auto &hot_slot = penumbra->tlb[TLB_WRITE][slot];
        if (hot_slot.vaddr_page == TLB_INVALID_PAGE || hot_slot.vaddr_page == TLB_UNVERIFIED_PAGE) {
            continue;
        }
        const uint64_t slot_hpage = hot_slot.vaddr_page + static_cast<uint64_t>(hot_slot.vh_offset);
        if (cp_hpage_traced(c, slot_hpage)) {
            hot_slot.vaddr_page = TLB_UNVERIFIED_PAGE;
            hot_slot.vh_offset = host_addr{0};
        }
    }
    // Same-page pending links (RVVM policy: link when either end installs).
    // Bodies bake their recording context, so a link requires both mapping
    // and context equality. Cross-page successors keep the island: their
    // fetch fills belong to the interpreter.
    const uint16_t idx = static_cast<uint16_t>(c->ntraces - 1);
    c->link_next[idx] = cp_state::none_link;
    {
        // Predecessors already waiting on this head.
        uint32_t slot = cp_pc_slot(t.head);
        const uint64_t tag = t.head + 1;
        while (c->pending_link_pc[slot] != 0 && c->pending_link_pc[slot] != tag) {
            slot = (slot + 1) & (cp_state::set_slots - 1);
        }
        if (c->pending_link_pc[slot] == tag) {
            uint16_t p = c->pending_link_trace[slot];
            c->pending_link_trace[slot] = cp_state::none_link;
            uint16_t keep = cp_state::none_link;
            while (p != cp_state::none_link) {
                cp_trace &pred = c->pool[p];
                const uint16_t next = c->link_next[p];
                // Same page AND same vf: only vf equality proves the
                // successor's body was recorded from the same host bytes the
                // predecessor validated at entry (the same virtual page can
                // hold different content across mapping epochs, and the old
                // trace stays alive because its own host page was never
                // written).
                if (!pred.dead && pred.link_site != 0 && pred.link_target == cp_state::none_link &&
                    pred.code_vf_offset == t.code_vf_offset && pred.ctx_slot_base == t.ctx_slot_base) {
                    cp_patch_branch(c->heap.base + pred.link_site, pred.link_kind, pred.link_addend,
                        const_cast<uint8_t *>(static_cast<const uint8_t *>(t.fn)));
                    cp_heap_lower(&c->heap, pred.link_site);
                    pred.link_target = idx;
                    ++c->links;
                } else if (!pred.dead && pred.link_site != 0 && pred.link_target == cp_state::none_link &&
                    pred.code_vf_offset == t.code_vf_offset) {
                    ++c->context_link_rejects;
                    c->link_next[p] = keep;
                    keep = p;
                }
                p = next;
            }
            c->pending_link_trace[slot] = keep;
        }
    }
    if (!cyclic && t.link_site != 0 && tlb_addr_page(t.successor) == tlb_addr_page(t.head)) {
        // This trace's own straight exit: link now or register as pending.
        // The vf equality requirement is the content check described above.
        bool interpreted = false;
        bool linked = false;
        if (const cp_trace *succ = cp_find(c, t.successor, &interpreted); succ != nullptr) {
            if (succ->code_vf_offset == t.code_vf_offset && succ->ctx_slot_base == t.ctx_slot_base) {
                cp_patch_branch(c->heap.base + t.link_site, t.link_kind, t.link_addend,
                    const_cast<uint8_t *>(static_cast<const uint8_t *>(succ->fn)));
                cp_heap_lower(&c->heap, t.link_site);
                t.link_target = static_cast<uint16_t>(succ - c->pool);
                ++c->links;
                linked = true;
            } else if (succ->code_vf_offset == t.code_vf_offset) {
                ++c->context_link_rejects;
            }
        }
        if (!linked && !interpreted) {
            cp_pending_link_add(c, idx);
        }
    }
    cp_heap_protect_flush(&c->heap);

    if (cp_log_enabled()) [[unlikely]] {
        int fin_guests = 0;
        for (int g = 1; g < 32; ++g) {
            fin_guests += c->reg_slot[g] >= 0 ? 1 : 0;
        }
        std::fprintf(stderr, "cp-fin head=%llx end=%llx len=%u %s%s guests=%d slots=%u\n",
            static_cast<unsigned long long>(t.head), static_cast<unsigned long long>(c->rec_end_vaddr), t.len,
            cyclic ? "cyclic" : "straight", t.carried ? " carried" : "", fin_guests, c->nslots_used);
    }
    if (std::getenv("CP_DUMP_CODE") != nullptr) [[unlikely]] {
        char path[64];
        std::snprintf(path, sizeof(path), "/tmp/cp-trace-%llx.bin", static_cast<unsigned long long>(t.head));
        if (std::FILE *fdump = std::fopen(path, "wb")) {
            std::fwrite(t.code_start, 1, t.code_size, fdump);
            std::fclose(fdump);
        }
        std::fprintf(stderr, "cp: trace head %llx len %u code %u bytes vf %llx %s\n",
            static_cast<unsigned long long>(t.head), t.len, t.code_size,
            static_cast<unsigned long long>(t.code_vf_offset), cyclic ? "cyclic" : "straight");
    }
}

template <typename STATE_ACCESS>
static void cp_begin(const STATE_ACCESS a, tc_context<STATE_ACCESS> *tcc, uint64_t vpc) {
    cp_state *c = tcc->cp;
    if (c->ntraces >= cp_state::max_traces) {
        cp_flush(c);
    }
    const uint64_t t0 = cp_now_ns();
    cp_heap_unprotect(&c->heap);
    c->recording = true;
    c->rec_failed = false;
    c->rec_head = vpc;
    c->rec_vaddr = vpc;
    c->rec_end_vaddr = vpc;
    c->rec_code_vf_offset = static_cast<uint64_t>(tcc->fetch_vaddr_page) - tlb_addr_page(vpc);
    c->rec_ctx_slot_base = a.get_penumbra().tlb_ctx_slot_base;
    c->rec_alloc_start = static_cast<uint64_t>(c->heap.curr);
    c->rec_len = 0;
    c->rec_nhpages = 0;
    for (auto &r : c->reg_slot) {
        r = -1;
    }
    c->reg_dirty = 0;
    c->nslots_used = 0;
    for (auto &u : c->rec_last_used) {
        u = 0;
    }
    c->rec_use_clock = 0;
    c->have_pending_branch = false;
    c->nbails = 0;
    c->rec_log_len = 0;
    c->rec_carry_ok = true;
    c->rec_guest_slots = 0;
    c->rec_scratch_slots = 0;
    c->fusion_ninsns = 0;
    c->fusion_nthings = 0;
    // The call prologue probes the recording context's hot code-TLB slot. It
    // compares the recorded vh for content identity, re-encodes the pc from
    // the incoming deposit, and publishes the mapping; the final stencil
    // publishes the entry-time pma from the shadow slot of the same index. A
    // miss bails with the deposit untouched and resumes the fetch path.
    static_assert(offsetof(penumbra_state, tlb_ctx_slot_base) - offsetof(penumbra_state, fetch_vf_offset) == 8,
        "cp_call_probe derives the vf address from the ctx address");
    static_assert(sizeof(hot_tlb_slot) == 16, "cp_call_probe bakes the hot slot size");
    static_assert(TLB_NUM_CTX == 4 && TLB_SET_SIZE == 256, "cp_call_probe bakes the context geometry");
    static_assert(sizeof(shadow_tlb_slot) == 32 && offsetof(shadow_tlb_slot, pma_index) == 16,
        "cp_call_pma bakes the shadow slot layout");
    constexpr size_t cp_tcc_fetch_page_off = 32; // matches the generator's literal
    constexpr size_t cp_tcc_pma_off = 40;        // matches the generator's literal
    static_assert(offsetof(tc_context<STATE_ACCESS>, fetch_vaddr_page) == cp_tcc_fetch_page_off,
        "cp_call_probe bakes the tcc offset");
    static_assert(offsetof(tc_context<STATE_ACCESS>, fetch_pma_index) == cp_tcc_pma_off,
        "cp_call_pma bakes the tcc offset");
    uint8_t *fall[2] = {nullptr, nullptr};
    penumbra_state &penumbra = a.get_penumbra();
    auto *const pstate =
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<processor_state *>(
            reinterpret_cast<unsigned char *>(&penumbra) - offsetof(processor_state, penumbra));
    c->rec_call_start = c->heap.base + c->heap.curr;
    const uint64_t imm_probe[4] = {reinterpret_cast<uint64_t>(&penumbra.tlb[TLB_CODE][0]), tlb_addr_page(vpc),
        c->rec_code_vf_offset, reinterpret_cast<uint64_t>(&penumbra.tlb_ctx_slot_base)};
    const uint64_t imm_pma[4] = {reinterpret_cast<uint64_t>(&pstate->shadow.tlb[TLB_CODE][0]), 0, 0, 0};
    uint8_t *probe_bail[2] = {nullptr, const_cast<uint8_t *>(static_cast<const uint8_t *>(c->page_island))};
    if (cp_emit(&c->heap, &cp_s_cp_call_probe, imm_probe, probe_bail) == nullptr ||
        cp_emit(&c->heap, &cp_s_cp_call_pma, imm_pma, fall) == nullptr) {
        c->rec_failed = true;
    }
    c->rec_body_start = c->heap.base + c->heap.curr; // replay rollback point
    // Entry: tick guard whose pending hole is re-patched at finish, bailing
    // to the island (countdown too low to run any of the body).
    const uint64_t imm[2] = {0, 0};
    uint8_t *cont[2] = {nullptr, const_cast<uint8_t *>(static_cast<const uint8_t *>(c->tick_island))};
    c->rec_tick_site = cp_emit(&c->heap, &cp_s_cp_tick_guard, imm, cont);
    c->rec_start = c->rec_tick_site;
    if (cp_log_enabled()) [[unlikely]] {
        std::fprintf(stderr, "cp-begin head=%llx\n", static_cast<unsigned long long>(vpc));
    }
    if (c->rec_tick_site == nullptr) {
        c->rec_failed = true;
    }
    c->begin_ns = t0;
}

// Records (and immediately emits) one executed instruction. Returns false
// when the recording ended and the caller should stop clamping chains.
template <typename STATE_ACCESS>
static void cp_record(const STATE_ACCESS a, tc_context<STATE_ACCESS> *tcc, uint64_t hpc, uint64_t vpc, uint32_t insn) {
    cp_state *c = tcc->cp;
    cp_former f{c, vpc};

    // Resolve the direction of the branch recorded one instruction ago.
    if (c->have_pending_branch) {
        c->have_pending_branch = false;
        const uint64_t taken = c->pb_taken_target;
        const uint64_t fall = c->pb_vaddr + c->pb_size;
        if (!cp_fusion_resolve_lbu_bne(c, vpc)) {
            const int s1 = f.alloc_src(c->pb_rs1);
            const int s2 = f.alloc_src(c->pb_rs2);
            if (!c->rec_failed) {
                if (vpc == taken) {
                    f.pc = c->pb_vaddr;
                    f.guard_branch(c->pb_tab[s1][s2], static_cast<int64_t>(fall - c->rec_head));
                } else if (vpc == fall) {
                    f.pc = c->pb_vaddr;
                    f.guard_branch(c->pb_comp[s1][s2], static_cast<int64_t>(taken - c->rec_head));
                } else {
                    c->rec_failed = true; // trap between: boundary cancel races
                }
                f.pc = vpc;
            }
        }
        if (!c->rec_failed) {
            ++c->rec_len;
            c->rec_end_vaddr = vpc; // the resolved direction is the successor
        }
    }
    if (c->rec_failed) {
        cp_finish(tcc, false);
        return;
    }

    // A trap between two recorded instructions lands this record call at the
    // handler instead of the architectural successor: the recorded body is
    // still valid (memory ops are guarded, branch directions validated), and
    // rec_end_vaddr already holds its correct exit target.
    if (vpc != c->rec_end_vaddr) {
        ++c->fin_trap;
        cp_finish(tcc, false);
        return;
    }

    // Mechanism checks kept from tc_online_record: mapping change ends the
    // trace before this instruction; revisiting the head with the same
    // mapping closes a cycle.
    const uint64_t vf = static_cast<uint64_t>(tcc->fetch_vaddr_page) - tlb_addr_page(vpc);
    if (vpc == c->rec_head && vf == c->rec_code_vf_offset && c->rec_len > 0) {
        ++c->fin_cyclic;
        cp_finish(tcc, true);
        return;
    }
    // Traces are guest-page-local (the whole instruction inside the head
    // page): the interpreter's code-TLB fills at page crossings are shadow
    // (hashed) state, so replay must reach every crossing in the
    // interpreter. In-trace crossings return with the validated-entry
    // translation node in increment 2.
    const uint64_t head_page = tlb_addr_page(c->rec_head);
    if (tlb_addr_page(vpc) != head_page || tlb_addr_page(vpc + 3) != head_page || vf != c->rec_code_vf_offset ||
        cp_find(c, vpc) != nullptr || c->rec_len >= cp_state::max_len) {
        if (tlb_addr_page(vpc) != head_page || tlb_addr_page(vpc + 3) != head_page || vf != c->rec_code_vf_offset) {
            ++c->fin_page;
        } else if (c->rec_len >= cp_state::max_len) {
            ++c->fin_maxlen;
        } else {
            ++c->fin_installed;
        }
        cp_finish(tcc, false);
        return;
    }

    // Track the host pages holding this instruction's bytes (the fast pc is
    // the host address of the executing bytes).
    const uint64_t hpage = hpc & ~PAGE_OFFSET_MASK;
    bool seen = false;
    for (uint8_t j = 0; j < c->rec_nhpages; ++j) {
        seen = seen || c->rec_hpage[j] == hpage;
    }
    if (!seen) {
        if (c->rec_nhpages >= cp_trace::max_hpages) {
            cp_finish(tcc, false);
            return;
        }
        c->rec_hpage[c->rec_nhpages++] = hpage;
    }

    const uint16_t id = static_cast<uint16_t>(insn_get_id(insn));
    const tc_label label = cp_label_table[id];
    const uint8_t size = cp_label_size[static_cast<uint16_t>(label)];
    if (cp_log_enabled()) [[unlikely]] {
        std::fprintf(stderr, "cp-rec head=%llx vpc=%llx len=%u\n", static_cast<unsigned long long>(c->rec_head),
            static_cast<unsigned long long>(vpc), c->rec_len);
    }
    c->rec_insn_start = c->heap.base + c->heap.curr;
    cp_save_checkpoint(c, c->rec_insn_checkpoint);
    c->rec_vaddr = vpc;
    c->rec_end_vaddr = vpc + size;
    const uint64_t pc = vpc;

#include "cp-select.inc"

    if (!c->rec_failed) {
        cp_fusion_record(c, vpc, insn, label, c->rec_insn_checkpoint);
    }

    if (!c->rec_failed && f.dynamic_slot >= 0) {
        ++c->rec_len;
        ++c->fin_dynamic;
        cp_finish(tcc, false, f.dynamic_slot);
        return;
    }
    if (c->rec_failed) {
        // Roll back this instruction and finish with what preceded it,
        // restoring the register-cache bookkeeping the failed allocations
        // mutated (their emitted spills are being discarded too).
        cp_restore_checkpoint(c, c->rec_insn_checkpoint);
        c->rec_end_vaddr = vpc;
        c->rec_failed = false;
        ++c->fin_uncompilable;
        if (cp_log_enabled()) [[unlikely]] {
            std::fprintf(stderr, "cp-uncomp vpc=%llx insn=%08x label=%u\n", static_cast<unsigned long long>(vpc), insn,
                static_cast<unsigned>(label));
        }
        cp_finish(tcc, false);
        return;
    }
    if (!c->have_pending_branch) {
        ++c->rec_len; // branches count when their direction resolves
    }
}

// ---------------------------------------------------------------------------
// Entry hook (RVVM policy: no counters) and the interpreter continuation.

template <bool CALL_ENTRY = false, typename STATE_ACCESS>
static FORCE_INLINE const void *cp_hook_site(tc_context<STATE_ACCESS> *tcc, uint64_t vpc) {
    cp_state *c = tcc->cp;
    if (c == nullptr) {
        return nullptr;
    }
    if (!c->recording) {
        bool interpreted = false;
        const cp_trace *t = cp_find(c, vpc, &interpreted);
        auto *const penumbra = reinterpret_cast<penumbra_state *>(
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<unsigned char *>(tcc) - offsetof(penumbra_state, scratch));
        if (t != nullptr && t->ctx_slot_base != penumbra->tlb_ctx_slot_base) {
            ++c->context_misses;
            cp_retire_context_trace(c, *const_cast<cp_trace *>(t));
            t = nullptr;
            interpreted = false;
        }
        if (t != nullptr) {
            cp_probe(c, penumbra, vpc);
        }
        if (t != nullptr && !cp_enter_allowed(c)) {
            return nullptr;
        }
        if (t != nullptr) {
            if constexpr (CALL_ENTRY) {
                // The C lookup has admitted the recording context. The
                // context-banked front cache provides the same guarantee to
                // generated entries; the shared call prologue validates the
                // hot code-TLB mapping.
                ++c->entries;
                ++c->call_entries;
                ++const_cast<cp_trace *>(t)->exec_count;
                cp_front_put(c, t->ctx_slot_base, vpc, t->call_fn);
                if (cp_log_enabled()) [[unlikely]] {
                    std::fprintf(stderr, "cp-callenter vpc=%llx len=%u\n", static_cast<unsigned long long>(vpc),
                        t->len);
                }
                return t->call_fn;
            } else {
                // Mapping AND translation-context must match the formation
                // state: under another context the interpreter would fill
                // the other code-TLB partition, and those fills are hashed.
                if (t->code_vf_offset == static_cast<uint64_t>(tcc->fetch_vaddr_page) - tlb_addr_page(vpc) &&
                    t->ctx_slot_base == penumbra->tlb_ctx_slot_base) {
                    ++c->entries;
                    ++const_cast<cp_trace *>(t)->exec_count;
                    if (cp_log_enabled()) [[unlikely]] {
                        std::fprintf(stderr, "cp-enter mcycle=%llu vpc=%llx len=%u\n",
                            static_cast<unsigned long long>(tcc->mcycle), static_cast<unsigned long long>(vpc), t->len);
                    }
                    return t->fn;
                }
                return nullptr;
            }
        }
        if (!interpreted) {
            tcc->online_trip_pc = vpc;
            tcc->online_trip = true;
        }
    }
    return nullptr;
}
