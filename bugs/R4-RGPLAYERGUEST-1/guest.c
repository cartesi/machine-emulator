/* Rollup guest that always accepts and never emits outputs, so its outputs Merkle root is always the root
 * of the empty outputs tree. It writes that root to the tx buffer and yields manual RX_ACCEPTED with a
 * length chosen by the first byte of the input:
 *   'z' -> DATA 0,   'Z' -> DATA 0xffffffff,   anything else (or the template's first yield) -> DATA 32.
 * The yield DATA field is guest-writable; the transition function does not interpret it (THREAT_MODEL
 * section 4: the outputs Merkle root is opaque guest data). */
#include "cm-baremetal.h"

static cm_outputs_tree tree;

int main(void) {
    uint8_t root[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    uint64_t req = cm_rollup_accept(root);
    for (;;) {
        uint32_t len = cm_request_length(req);
        uint32_t data = CM_HASH_SIZE;
        if (len >= 1) {
            uint8_t c = CM_RX_BUFFER[0];
            if (c == 'z') data = 0;
            else if (c == 'Z') data = 0xffffffffu;
        }
        for (uint32_t i = 0; i < CM_HASH_SIZE; i++) CM_TX_BUFFER[i] = root[i];
        req = cm_yield_manual(HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, data);
    }
}
