// Copy-and-patch interpreter continuation, split from interpret-cp.inc so
// its body sits after the fetch-tail machinery it rides (TC_SEG_TIGHTEN,
// tc_jumptable, tc_fetch_miss), like tc_lightning_continue does.

template <typename STATE_ACCESS>
TC_CALLCONV static execute_status cp_continue(const STATE_ACCESS a, uint32_t insn TC_HOT_PARAMS) {
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

