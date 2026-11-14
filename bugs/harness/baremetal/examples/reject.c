/* Starts like a valid template (accepted with the empty outputs root), then rejects every request. */
#include "cm-baremetal.h"
static cm_outputs_tree tree;
int main(void) {
    uint8_t root[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    (void) cm_rollup_accept(root);
    for (;;) {
        (void) cm_rollup_reject();
    }
}
