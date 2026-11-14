/* Valid-template-style rollup guest: yields manual RX_ACCEPTED with the empty outputs root, then accepts
 * every request (advance or inspect) without emitting outputs. Never halts. */
#include "cm-baremetal.h"
static cm_outputs_tree tree;
int main(void) {
    uint8_t root[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    for (;;) {
        (void) cm_rollup_accept(root);
    }
}
