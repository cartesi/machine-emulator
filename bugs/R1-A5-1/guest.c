/* R1-A5-1 guest: a rollup application that, for each advance-state request, emits one voucher
 *   Voucher(address destination, uint256 value, bytes payload) = (0x...a5a5, 0, "")
 * (selector 0x237a816f, ABI-encoded as cartesi-rollups-contracts decodes outputs), adds keccak256 of the
 * voucher bytes to its outputs Merkle tree (height 63) and accepts with the new root. Inspect-state requests
 * are accepted with the unchanged root. It follows the rollup interface on every input. */
#include "cm-baremetal.h"
static cm_outputs_tree tree;
#define VOUCHER_LEN (4 + 32 * 4)
int main(void) {
    uint8_t root[CM_HASH_SIZE], leaf[CM_HASH_SIZE];
    uint8_t voucher[VOUCHER_LEN];
    for (int i = 0; i < VOUCHER_LEN; i++) {
        voucher[i] = 0;
    }
    voucher[0] = 0x23; voucher[1] = 0x7a; voucher[2] = 0x81; voucher[3] = 0x6f; /* selector */
    voucher[4 + 31] = 0xa5; voucher[4 + 30] = 0xa5;                             /* destination 0x...a5a5 */
    voucher[4 + 3 * 32 - 1] = 0x60;                                             /* payload offset */
    /* value = 0, payload length = 0 */
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    uint64_t req = cm_rollup_accept(root);
    for (;;) {
        if (cm_request_reason(req) == HTIF_YIELD_REASON_ADVANCE_STATE_DEF) {
            cm_rollup_emit_output(voucher, VOUCHER_LEN);
            cm_keccak256(voucher, VOUCHER_LEN, leaf);
            cm_outputs_push(&tree, leaf);
            cm_outputs_root(&tree, root);
        }
        req = cm_rollup_accept(root);
    }
}
