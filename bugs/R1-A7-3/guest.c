/* R1-A7-3 guest: a correctly designed rollup application whose work per input is bounded by the input
 * itself. It waits at a manual yield with the accepted reason and the empty outputs root. For each request,
 * it reads the first 8 bytes of the rx buffer as a little-endian iteration count, spins that many times
 * (2 instructions per iteration), and accepts again with the empty outputs root. */
#include "cm-baremetal.h"
static cm_outputs_tree tree;
int main(void) {
    uint8_t root[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    uint64_t request = cm_rollup_accept(root);
    for (;;) {
        uint64_t n = 0;
        if (cm_request_length(request) >= 8) {
            for (int i = 7; i >= 0; i--) {
                n = (n << 8) | CM_RX_BUFFER[i];
            }
        }
        if (n) {
            __asm__ volatile("1: addi %0, %0, -1\n\tbnez %0, 1b" : "+r"(n));
        }
        request = cm_rollup_accept(root);
    }
}
