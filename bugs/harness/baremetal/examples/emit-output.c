/* Rollup guest that, for each advance-state request, emits the whole request (the raw rx-buffer bytes, i.e.
 * the ABI-encoded EvmAdvance) as one output and a one-byte report, adds keccak256(output) to its outputs
 * Merkle tree and accepts with the new root. Inspect-state requests are accepted with the unchanged root.
 * The first byte of the payload, if the request is shorter than 4 bytes, selects special behaviors:
 *   request length 1 and byte 'R' -> reject; byte 'H' -> halt(7); byte 'E' -> exception "boom". */
#include "cm-baremetal.h"
static cm_outputs_tree tree;
static uint8_t buf[CM_RX_BUFFER_SIZE];
int main(void) {
    uint8_t root[CM_HASH_SIZE], leaf[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    uint64_t req = cm_rollup_accept(root);
    for (;;) {
        uint16_t reason = cm_request_reason(req);
        uint32_t len = cm_request_length(req);
        if (len > CM_RX_BUFFER_SIZE) {
            len = CM_RX_BUFFER_SIZE;
        }
        for (uint32_t i = 0; i < len; i++) {
            buf[i] = CM_RX_BUFFER[i];
        }
        if (len == 1 && buf[0] == 'R') {
            req = cm_rollup_reject();
            continue;
        }
        if (len == 1 && buf[0] == 'H') {
            cm_halt(7);
        }
        if (len == 1 && buf[0] == 'E') {
            req = cm_rollup_exception("boom", 4);
            continue;
        }
        if (reason == HTIF_YIELD_REASON_ADVANCE_STATE_DEF) {
            if (len > CM_TX_BUFFER_SIZE) {
                len = CM_TX_BUFFER_SIZE;
            }
            cm_rollup_emit_output(buf, len);
            cm_keccak256(buf, len, leaf);
            cm_outputs_push(&tree, leaf);
            cm_rollup_emit_report("r", 1);
            cm_outputs_root(&tree, root);
        }
        req = cm_rollup_accept(root);
    }
}
