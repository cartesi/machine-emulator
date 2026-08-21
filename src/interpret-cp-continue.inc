// Copy-and-patch interpreter continuations, split from interpret-cp.inc so
// their bodies sit after the fetch-tail machinery they ride (TC_SEG_TIGHTEN,
// tc_jumptable, tc_fetch_miss), like tc_lightning_continue does.
//
// Two continuations give every trace exit RVVM's dispatcher semantics with
// no livelock: exits through exit stubs and lookup misses land on
// cp_continue, which enters an installed trace through its self-validating
// call entry, trips recording on a genuine miss, and otherwise resumes the
// fetch tail; entries that fail validation or the tick guard land on
// cp_continue_cold, which only resumes the fetch tail, so a failing entry
// is attempted at most once per exit.

template <typename STATE_ACCESS>
TC_CALLCONV static execute_status cp_continue_cold(const STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS) {
    TC_ENTER();
    if (fetch_cache_is_hit(pc, TC_FETCH_TAG)) [[likely]] {
        uint32_t next_insn = 0;
        TC_SEG_TIGHTEN();
        a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index, &next_insn);
        TC_SYNC();
        TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(next_insn)](a, next_insn TC_HOT_ARGS);
    }
    TC_SYNC();
    TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);
}

template <typename STATE_ACCESS>
TC_CALLCONV static execute_status cp_continue(const STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS) {
    TC_ENTER();
    cp_state *const c = tcc->cp;
    if (!c->recording) [[likely]] {
        const uint64_t vpc = pc_to_virtual(a, pc);
        bool interpreted = false;
        if (const cp_trace *t = cp_find(c, vpc, &interpreted); t != nullptr) {
            // Installed: enter through the self-validating call entry (its
            // validation bails reach cp_continue_cold, never back here).
            ++c->continue_enters;
            cp_front_put(c, vpc, t->call_fn);
            TC_SYNC();
            TC_MUSTTAIL return reinterpret_cast<tc_handler_ptr<STATE_ACCESS>>(const_cast<void *>(t->call_fn))(a,
                insn TC_HOT_ARGS);
        }
        if (!interpreted) {
            // Genuine miss: compile on first miss, RVVM's dispatcher policy,
            // so return continuations and off-path resumption points form
            // traces instead of staying interpreted forever.
            ++c->continue_trips;
            tcc->online_trip_pc = vpc;
            tcc->online_trip = true;
            TC_SYNC();
            TC_RETURN(execute_status::success);
        }
    }
    if (fetch_cache_is_hit(pc, TC_FETCH_TAG)) [[likely]] {
        uint32_t next_insn = 0;
        TC_SEG_TIGHTEN();
        a.template read_memory_word<uint32_t, uint16_t>(pc, tcc->fetch_pma_index, &next_insn);
        TC_SYNC();
        TC_MUSTTAIL return tc_jumptable<STATE_ACCESS>[insn_get_id(next_insn)](a, next_insn TC_HOT_ARGS);
    }
    TC_SYNC();
    TC_MUSTTAIL return tc_fetch_miss<STATE_ACCESS>(a, insn TC_HOT_ARGS);
}
