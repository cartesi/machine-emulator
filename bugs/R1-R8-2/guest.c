/* R1-R8-2 guest. Accepts at start with the empty outputs root, then for each advance-state input:
 *   "O" + u32 little-endian N : emits N outputs of 2 MiB (the whole tx buffer, identical bytes), then accepts
 *                               with the correct cumulative outputs Merkle root (a correctly designed app);
 *   "W"                       : emits nothing and accepts with a root that is NOT the root of its outputs
 *                               (an application that breaks the rollup interface, or a subverted guest);
 *   anything else             : accepts with the unchanged root. */
#include "cm-baremetal.h"
static cm_outputs_tree tree;
static uint8_t big[CM_TX_BUFFER_SIZE];
int main(void) {
    uint8_t root[CM_HASH_SIZE], leaf[CM_HASH_SIZE];
    for (uint32_t i = 0; i < CM_TX_BUFFER_SIZE; i++) {
        big[i] = (uint8_t) (i * 131u + 7u);
    }
    cm_keccak256(big, CM_TX_BUFFER_SIZE, leaf);
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    uint64_t req = cm_rollup_accept(root);
    for (;;) {
        uint16_t reason = cm_request_reason(req);
        uint32_t len = cm_request_length(req);
        if (reason == HTIF_YIELD_REASON_ADVANCE_STATE_DEF && len >= 5 && CM_RX_BUFFER[0] == 'O') {
            uint32_t n = (uint32_t) CM_RX_BUFFER[1] | ((uint32_t) CM_RX_BUFFER[2] << 8) |
                ((uint32_t) CM_RX_BUFFER[3] << 16) | ((uint32_t) CM_RX_BUFFER[4] << 24);
            for (uint32_t k = 0; k < n; k++) {
                cm_rollup_emit_output(big, CM_TX_BUFFER_SIZE);
                cm_outputs_push(&tree, leaf);
            }
            cm_outputs_root(&tree, root);
            req = cm_rollup_accept(root);
        } else if (reason == HTIF_YIELD_REASON_ADVANCE_STATE_DEF && len >= 1 && CM_RX_BUFFER[0] == 'W') {
            uint8_t wrong[CM_HASH_SIZE];
            for (int i = 0; i < CM_HASH_SIZE; i++) {
                wrong[i] = (uint8_t) (root[i] ^ 0x5a);
            }
            req = cm_rollup_accept(wrong);
        } else {
            req = cm_rollup_accept(root);
        }
    }
}
