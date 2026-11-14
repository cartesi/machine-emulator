/* R1-R8-1 guest: a bare-metal rollup guest whose inputs choose how many outputs it emits.
 *
 * Boot: accept with the root of the empty outputs tree (valid-template style).
 * Each advance-state request carries, little-endian:
 *   u64 count        number of outputs to emit, each as one automatic TX_OUTPUT yield; output i (from 0)
 *                    is the tx buffer with its first 8 bytes set to i (little-endian), so outputs differ
 *   u32 length       length each output declares in the yield (8 = just the counter; > 2 MiB = oversized,
 *                    whose bytes are then the whole 2 MiB tx buffer)
 *   u32 pad
 *   u64 mcycles      after the outputs, spin until mcycle >= (mcycle at input start) + mcycles, so that
 *                    inputs with different output counts can run the same number of mcycles
 *   u8  root[32]     outputs Merkle root to accept with (computed by the host test)
 * Before emitting, the first 32 bytes of the tx buffer are cleared (the rest of it is never written), so
 * every output's bytes are known to the host.
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
        uint32_t declared = (uint32_t) rd64(8);
        uint64_t mcycles = rd64(16);
        for (int i = 0; i < CM_HASH_SIZE; i++) {
            root[i] = CM_RX_BUFFER[24 + i];
            CM_TX_BUFFER[i] = 0;
        }
        for (uint64_t i = 0; i < count; i++) {
            *(volatile uint64_t *) CM_TX_BUFFER = i; /* RV64 is little-endian */
            cm_yield_automatic(HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF, declared);
        }
        while (rd_mcycle() - start < mcycles) {
        }
        req = cm_rollup_accept(root);
    }
}
