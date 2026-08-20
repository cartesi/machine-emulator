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
    c->ntraced_pages = 0;
    c->recording = false;
    ++c->flushes;
}

static void cp_free(void *p) {
    auto *c = static_cast<cp_state *>(p);
    if (std::getenv("CP_STATS") != nullptr) {
        std::fprintf(stderr,
            "cp: installed %llu empty-marked %llu invalidated %llu flushes %llu emitted %llu bytes "
            "compile-ms %llu entries %llu call-entries %llu links %llu severed %llu\n",
            static_cast<unsigned long long>(c->installed), static_cast<unsigned long long>(c->empty_marked),
            static_cast<unsigned long long>(c->invalidated), static_cast<unsigned long long>(c->flushes),
            static_cast<unsigned long long>(c->emitted_bytes), static_cast<unsigned long long>(c->compile_ns / 1000000),
            static_cast<unsigned long long>(c->entries), static_cast<unsigned long long>(c->call_entries),
            static_cast<unsigned long long>(c->links), static_cast<unsigned long long>(c->links_severed));
    }
    cp_heap_free(&c->heap);
    delete c;
}

template <typename STATE_ACCESS>
TC_CALLCONV static execute_status cp_continue(STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS);

static cp_state *cp_get(penumbra_state &penumbra, const void *continue_fn) {
    if (penumbra.tc_state == nullptr) {
        auto *c = new cp_state{};
        if (cp_heap_init(&c->heap, 64u << 20) != 0) {
            delete c;
            return nullptr;
        }
        // The far-jump island through which every exit reaches the
        // interpreter continuation, emitted once per heap.
        cp_heap_unprotect(&c->heap);
        const uint64_t imm[2] = {reinterpret_cast<uint64_t>(continue_fn), 0};
        uint8_t *island_cont[2] = {nullptr, nullptr};
        c->continue_island = cp_emit(&c->heap, &cp_s_cp_far_jump, imm, island_cont);
        cp_heap_protect_flush(&c->heap);
        c->heap_reset_curr = c->heap.curr;
        penumbra.tc_state = c;
        penumbra.tc_state_free = &cp_free;
    }
    return static_cast<cp_state *>(penumbra.tc_state);
}

// ---------------------------------------------------------------------------
// Formation: the emitter-facing former the selection include drives.

struct cp_former {
    cp_state *c;
    uint64_t pc; // guest vaddr of the instruction being recorded

    // Slot-level emission. cont[0] null means fallthrough (elided).
    uint8_t *emit1(const cp_stencil_t *st, uint64_t imm0 = 0, uint64_t imm1 = 0, uint8_t *bail = nullptr) {
        const uint64_t imm[2] = {imm0, imm1};
        uint8_t *cont[2] = {nullptr, bail};
        uint8_t *at = cp_emit(&c->heap, st, imm, cont);
        if (at == nullptr) {
            c->rec_failed = true;
        }
        return at;
    }

    // Guest-register slot allocation, RVVM's guest-indexed cache.
    // Returns the slot holding the register's value, loading lazily
    // (x0 loads a zero constant); -1 when slots are exhausted.
    int alloc_src(uint8_t reg) {
        if (c->reg_slot[reg] >= 0) {
            return c->reg_slot[reg];
        }
        if (c->nslots_used >= cp_state::nslots) {
            c->rec_failed = true;
            return -1;
        }
        const int slot = c->nslots_used++;
        c->slot_guest[slot] = reg;
        c->reg_slot[reg] = static_cast<int8_t>(slot);
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
            c->reg_dirty |= 1u << static_cast<uint32_t>(c->reg_slot[reg]);
            return c->reg_slot[reg];
        }
        if (c->nslots_used >= cp_state::nslots) {
            c->rec_failed = true;
            return -1;
        }
        const int slot = c->nslots_used++;
        c->slot_guest[slot] = reg;
        c->reg_slot[reg] = static_cast<int8_t>(slot);
        c->reg_dirty |= 1u << static_cast<uint32_t>(slot);
        return slot;
    }

    // A transient slot for materialized immediates and address arithmetic.
    int alloc_scratch() {
        if (c->nslots_used >= cp_state::nslots) {
            c->rec_failed = true;
            return -1;
        }
        const int slot = c->nslots_used++;
        c->slot_guest[slot] = 0xff;
        return slot;
    }
    void free_scratch(int slot) {
        if (slot == c->nslots_used - 1 && c->slot_guest[slot] == 0xff) {
            --c->nslots_used;
        }
    }

    // Guest-level primitives, called from cp-select.inc.
    void reg3(const cp_stencil_t *const (&tab)[7][7][7], uint8_t rd, uint8_t rs1, uint8_t rs2) {
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

    void reg2i(const cp_stencil_t *const (&tab)[7][7][7], uint8_t rd, uint8_t rs1, uint64_t imm) {
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

    void load(const cp_stencil_t *const (&tab)[7][7], uint8_t rd, uint8_t rs1, uint64_t imm) {
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
            emit_guarded(tab[t][base]);
            free_scratch(t);
            return;
        }
        const int d = alloc_dst(rd);
        if (c->rec_failed) {
            return;
        }
        emit_guarded(tab[d][base]);
        free_scratch(scratch);
    }

    void store(const cp_stencil_t *const (&tab)[7][7], uint8_t rs1, uint8_t rs2, uint64_t imm) {
        int scratch = -1;
        const int base = address(rs1, imm, scratch);
        const int val = alloc_src(rs2);
        if (c->rec_failed) {
            return;
        }
        emit_guarded(tab[base][val]);
        free_scratch(scratch);
    }

    // Emits a hit-or-bail stencil, deferring the bail block to finish.
    void emit_guarded(const cp_stencil_t *st) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        uint8_t *at = emit1(st, 0, 0, reinterpret_cast<uint8_t *>(this)); // placeholder target
        if (at == nullptr) {
            return;
        }
        // Locate the bail patch (ordinal 1) of this stencil to re-patch at
        // finish, once the grouped bail blocks exist.
        for (uint16_t i = 0; i < st->npatches; ++i) {
            const cp_patch_t *p = &st->patches[i];
            if ((p->kind == CP_P_JUMP26 || p->kind == CP_P_JMPREL32) && p->ordinal == 1) {
                cp_bail &b = c->bails[c->nbails++];
                b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
                b.guard_kind = p->kind;
                b.guard_addend = p->addend;
                b.delta = static_cast<int64_t>(pc - c->rec_head);
                b.pending = c->rec_len; // instructions fully retired before this one
                b.dirty = c->reg_dirty;
                return;
            }
        }
        c->rec_failed = true; // stencil without a bail continuation
    }

    // Branch guard with the recorded direction as fallthrough.
    void guard_branch(const cp_stencil_t *st, int64_t off_delta) {
        if (c->nbails >= cp_state::max_bails) {
            c->rec_failed = true;
            return;
        }
        uint8_t *at = emit1(st, 0, 0, reinterpret_cast<uint8_t *>(this));
        if (at == nullptr) {
            return;
        }
        for (uint16_t i = 0; i < st->npatches; ++i) {
            const cp_patch_t *p = &st->patches[i];
            if ((p->kind == CP_P_JUMP26 || p->kind == CP_P_JMPREL32) && p->ordinal == 1) {
                cp_bail &b = c->bails[c->nbails++];
                b.guard_site = static_cast<uint32_t>((at + p->offset) - c->heap.base);
                b.guard_kind = p->kind;
                b.guard_addend = p->addend;
                b.delta = off_delta;
                b.pending = c->rec_len + 1; // the branch itself retires on exit
                b.dirty = c->reg_dirty;
                return;
            }
        }
        c->rec_failed = true;
    }

    // Branches lag one record call: the direction is the next pc.
    void branch(const cp_stencil_t *const (&tab)[7][7], const cp_stencil_t *const (&comp)[7][7], uint8_t rs1,
        uint8_t rs2, uint64_t taken_target, uint8_t size) {
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

    void end() {
        c->rec_failed = true; // uncompilable: caller finishes before this insn
    }
};

// One-time env probe for the formation/entry debug log.
static bool cp_log_enabled() {
    static const bool enabled = std::getenv("CP_LOG") != nullptr;
    return enabled;
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

// Emits the stores for a dirty-slot snapshot.
static void cp_emit_stores(cp_state *c, uint32_t dirty) {
    for (uint32_t slot = 0; slot < cp_state::nslots; ++slot) {
        if ((dirty & (1u << slot)) != 0 && c->slot_guest[slot] != 0xff && c->slot_guest[slot] != 0) {
            const uint64_t imm[2] = {0, 0};
            uint8_t *cont[2] = {nullptr, nullptr};
            if (cp_emit(&c->heap, cp_gxs_table[slot][c->slot_guest[slot] - 1], imm, cont) == nullptr) {
                c->rec_failed = true;
            }
        }
    }
}

// Emits one exit: stores, relative exit stub, far jump to the island (or a
// direct branch to `target` when given, for the cyclic back edge). For the
// straight terminal, link_site receives the stub's trailing branch, the one
// site the pending-link pass may later retarget to a successor's entry.
static uint8_t *cp_emit_exit(cp_state *c, uint32_t dirty, int64_t delta, uint32_t pending, uint8_t *target = nullptr,
    cp_trace *link_out = nullptr) {
    uint8_t *at = c->heap.base + c->heap.curr;
    cp_emit_stores(c, dirty);
    uint8_t *stub = c->heap.base + c->heap.curr;
    const uint64_t imm[2] = {static_cast<uint64_t>(delta), pending};
    uint8_t *cont[2] = {target != nullptr ? target : const_cast<uint8_t *>(static_cast<const uint8_t *>(c->continue_island)),
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
        } else {
            const unsigned shift = 16u * static_cast<unsigned>(p->kind - CP_P_G0);
            uint32_t insn = 0;
            std::memcpy(&insn, site, 4);
            insn = (insn & ~(0xffffu << 5)) | ((static_cast<uint32_t>(value >> shift) & 0xffffu) << 5);
            std::memcpy(site, &insn, 4);
        }
    }
}

template <typename STATE_ACCESS>
static void cp_finish(tc_context<STATE_ACCESS> *tcc, bool cyclic) {
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

    // Terminal: cyclic traces store and loop to their own entry; straight
    // traces store and leave for the successor.
    if (cyclic) {
        cp_emit_exit(c, c->reg_dirty, 0, c->rec_len, c->rec_start);
    } else {
        cp_emit_exit(c, c->reg_dirty, static_cast<int64_t>(c->rec_end_vaddr - c->rec_head), c->rec_len, nullptr, &t);
    }

    // Grouped bail blocks, then patch each guard's bail branch.
    for (uint32_t i = 0; i < c->nbails && !c->rec_failed; ++i) {
        const cp_bail &b = c->bails[i];
        uint8_t *block = cp_emit_exit(c, b.dirty, b.delta, b.pending);
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
    t.fn = c->rec_start;
    t.call_fn = c->rec_call_start;
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
    // Exits are pc-relative and the trace bodies probe the TLB with the
    // runtime context, so a same-page retarget needs no vf or ctx equality,
    // and the successor's tick guard still runs. Cross-page successors keep
    // the island: their fetch fills belong to the interpreter.
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
            while (p != cp_state::none_link) {
                cp_trace &pred = c->pool[p];
                const uint16_t next = c->link_next[p];
                if (!pred.dead && pred.link_site != 0 && pred.link_target == cp_state::none_link) {
                    cp_patch_branch(c->heap.base + pred.link_site, pred.link_kind, pred.link_addend,
                        const_cast<uint8_t *>(static_cast<const uint8_t *>(t.fn)));
                    cp_heap_lower(&c->heap, pred.link_site);
                    pred.link_target = idx;
                    ++c->links;
                }
                p = next;
            }
        }
    }
    if (!cyclic && t.link_site != 0 && tlb_addr_page(t.successor) == tlb_addr_page(t.head)) {
        // This trace's own straight exit: link now or register as pending.
        bool interpreted = false;
        if (const cp_trace *succ = cp_find(c, t.successor, &interpreted); succ != nullptr) {
            cp_patch_branch(c->heap.base + t.link_site, t.link_kind, t.link_addend,
                const_cast<uint8_t *>(static_cast<const uint8_t *>(succ->fn)));
            cp_heap_lower(&c->heap, t.link_site);
            t.link_target = static_cast<uint16_t>(succ - c->pool);
            ++c->links;
        } else if (!interpreted) {
            uint32_t slot = cp_pc_slot(t.successor);
            const uint64_t tag = t.successor + 1;
            while (c->pending_link_pc[slot] != 0 && c->pending_link_pc[slot] != tag) {
                slot = (slot + 1) & (cp_state::set_slots - 1);
            }
            if (c->pending_link_pc[slot] == 0) {
                c->pending_link_pc[slot] = tag;
                c->pending_link_trace[slot] = cp_state::none_link;
            }
            c->link_next[idx] = c->pending_link_trace[slot];
            c->pending_link_trace[slot] = idx;
        }
    }
    cp_heap_protect_flush(&c->heap);

    if (cp_log_enabled()) [[unlikely]] {
        std::fprintf(stderr, "cp-fin head=%llx end=%llx len=%u %s\n",
            static_cast<unsigned long long>(t.head), static_cast<unsigned long long>(c->rec_end_vaddr), t.len,
            cyclic ? "cyclic" : "straight");
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
    c->have_pending_branch = false;
    c->nbails = 0;
    // Call-entry prologue (ported call_fn semantics): the hook enters here
    // only after validating the hot code-TLB slot against the recorded
    // mapping and context, so every established value is an install-time
    // constant. Mapping fields first, register re-encode last, with no C
    // boundary in between (the pc encoding and fetch_vf_offset must never
    // disagree at one); falls through into the tick guard, so call entries
    // sit behind the same tick check as lightning's established entry.
    uint8_t *fall[2] = {nullptr, nullptr};
    penumbra_state &penumbra = a.get_penumbra();
    const uint64_t vf = c->rec_code_vf_offset;
    const uint64_t fetch_val = tlb_addr_page(vpc) + vf;
    c->rec_call_start = c->heap.base + c->heap.curr;
    const uint64_t imm_vf[2] = {reinterpret_cast<uint64_t>(&penumbra.fetch_vf_offset), vf};
    const uint64_t imm_page[2] = {reinterpret_cast<uint64_t>(&tcc->fetch_vaddr_page), fetch_val};
    const uint64_t imm_est[2] = {vpc + vf, fetch_val};
    if (cp_emit(&c->heap, &cp_s_cp_store_imm, imm_vf, fall) == nullptr ||
        cp_emit(&c->heap, &cp_s_cp_store_imm, imm_page, fall) == nullptr ||
        cp_emit(&c->heap, &cp_s_cp_call_establish, imm_est, fall) == nullptr) {
        c->rec_failed = true;
    }
    // Entry: tick guard whose pending hole is re-patched at finish, bailing
    // to the island (countdown too low to run any of the body).
    const uint64_t imm[2] = {0, 0};
    uint8_t *cont[2] = {nullptr,
        const_cast<uint8_t *>(static_cast<const uint8_t *>(c->continue_island))};
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
        cp_finish(tcc, false);
        return;
    }

    // Mechanism checks kept from tc_online_record: mapping change ends the
    // trace before this instruction; revisiting the head with the same
    // mapping closes a cycle.
    const uint64_t vf = static_cast<uint64_t>(tcc->fetch_vaddr_page) - tlb_addr_page(vpc);
    if (vpc == c->rec_head && vf == c->rec_code_vf_offset && c->rec_len > 0) {
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
    c->rec_vaddr = vpc;
    c->rec_end_vaddr = vpc + size;
    const uint64_t pc = vpc;

#include "cp-select.inc"

    if (c->rec_failed) {
        // Roll back this instruction and finish with what preceded it.
        c->heap.curr = static_cast<size_t>(c->rec_insn_start - c->heap.base);
        c->rec_end_vaddr = vpc;
        c->rec_failed = false;
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
        if (t != nullptr) {
            auto *const penumbra = reinterpret_cast<penumbra_state *>(
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<unsigned char *>(tcc) - offsetof(penumbra_state, scratch));
            if constexpr (CALL_ENTRY) {
                // Ported call_fn semantics, validation hoisted into C and the
                // context check first: enter only when the hot code-TLB slot
                // of the head page, under the recorded context, still maps
                // the recorded host page. Any miss falls back to the
                // interpreter fetch, whose fill is the hashed behavior.
                if (penumbra->tlb_ctx_slot_base == t->ctx_slot_base) {
                    const uint64_t head_page = tlb_addr_page(t->head);
                    const uint64_t slot = tlb_slot_index(t->head, t->ctx_slot_base);
                    const auto &hot = penumbra->tlb[TLB_CODE][slot];
                    if (hot.vaddr_page == head_page && static_cast<uint64_t>(hot.vh_offset) == t->code_vf_offset) {
                        auto *const state = reinterpret_cast<processor_state *>(
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                            reinterpret_cast<unsigned char *>(penumbra) - offsetof(processor_state, penumbra));
                        // Entry-time state, like lightning's call_fn reads it;
                        // publishing before the prologue re-encodes the pc is
                        // safe because the stale fetch tag still misses, and
                        // every miss path recomputes the pma index.
                        tcc->fetch_pma_index = state->shadow.tlb[TLB_CODE][slot].pma_index;
                        ++c->entries;
                        ++c->call_entries;
                        if (cp_log_enabled()) [[unlikely]] {
                            std::fprintf(stderr, "cp-callenter vpc=%llx len=%u\n",
                                static_cast<unsigned long long>(vpc), t->len);
                        }
                        return t->call_fn;
                    }
                }
                return nullptr;
            } else {
                // Mapping AND translation-context must match the formation
                // state: under another context the interpreter would fill
                // the other code-TLB partition, and those fills are hashed.
                if (t->code_vf_offset == static_cast<uint64_t>(tcc->fetch_vaddr_page) - tlb_addr_page(vpc) &&
                    t->ctx_slot_base == penumbra->tlb_ctx_slot_base) {
                    ++c->entries;
                    if (cp_log_enabled()) [[unlikely]] {
                        std::fprintf(stderr, "cp-enter mcycle=%llu vpc=%llx len=%u\n",
                            static_cast<unsigned long long>(tcc->mcycle), static_cast<unsigned long long>(vpc),
                            t->len);
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

