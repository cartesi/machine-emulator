/* R2-DFYIELD-1 guest: a bare-metal rollup guest whose inputs choose how many automatic yields it makes,
 * with which reason, and which payload length each yield declares in tohost.
 *
 * Boot: accept with the root of the empty outputs tree (valid-template style).
 * Each advance-state request carries, little-endian:
 *   u64 count        number of automatic yields to make
 *   u32 declared     payload length each yield declares in tohost DATA (the guest writes only 8 bytes)
 *   u32 reason       automatic yield reason (HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT or _TX_REPORT)
 *   u64 mcycles      after the yields, spin until mcycle >= (mcycle at input start) + mcycles, so that
 *                    every case runs the same number of mcycles
 *   u8  root[32]     outputs Merkle root to accept with (computed by the host test)
 * Before yielding, the first 32 bytes of the tx buffer are cleared; yield i then writes the 8-byte counter i to
 * the first 8 bytes. Nothing else in the tx buffer is ever written, so it stays zero.
 */
#include "cm-baremetal.h"

static inline uint64_t rd_mcycle(void) {
    uint64_t v;
    __asm__ volatile("csrr %0, mcycle" : "=r"(v));
    return v;
}

static uint64_t rd64(uint32_t off) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | CM_RX_BUFFER[off + (uint32_t) i];
    }
    return v;
}

int main(void) {
    static cm_outputs_tree tree;
    uint8_t root[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    uint64_t req = cm_rollup_accept(root);
    for (;;) {
        uint64_t start = rd_mcycle();
        uint32_t len = cm_request_length(req);
        if (cm_request_reason(req) != HTIF_YIELD_REASON_ADVANCE_STATE_DEF || len < 56) {
            req = cm_rollup_reject();
            continue;
        }
        uint64_t count = rd64(0);
        uint64_t w = rd64(8);
        uint32_t declared = (uint32_t) w;
        uint16_t reason = (uint16_t) (w >> 32);
        uint64_t mcycles = rd64(16);
        for (int i = 0; i < CM_HASH_SIZE; i++) {
            root[i] = CM_RX_BUFFER[24 + i];
            CM_TX_BUFFER[i] = 0;
        }
        for (uint64_t i = 0; i < count; i++) {
            *(volatile uint64_t *) CM_TX_BUFFER = i; /* RV64 is little-endian */
            cm_yield_automatic(reason, declared);
        }
        while (rd_mcycle() - start < mcycles) {
        }
        req = cm_rollup_accept(root);
    }
}
