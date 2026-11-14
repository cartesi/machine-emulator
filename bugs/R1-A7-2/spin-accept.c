/* R1-A7-2 guest: a valid-template-style rollup application that spends a fixed amount of work on every
 * request and then accepts it with the empty outputs root (no outputs). Each request costs about
 * 2 * SPIN_ITERATIONS mcycles (a two-instruction loop), here 2^30, which is below Dave's own per-input compute
 * contract at the default snapshot gap (2^30.9, docs/dimensioning.md) and far below imcyclemax (2^48). */
#include "cm-baremetal.h"
#ifndef SPIN_ITERATIONS
#define SPIN_ITERATIONS (1UL << 29)
#endif
static cm_outputs_tree tree;
int main(void) {
    uint8_t root[CM_HASH_SIZE];
    cm_outputs_init(&tree);
    cm_outputs_root(&tree, root);
    (void) cm_rollup_accept(root); /* the template: waits at a manual yield, accepted, empty outputs root */
    for (;;) {
        uint64_t n = SPIN_ITERATIONS;
        __asm__ volatile("1: addi %0, %0, -1\n\tbnez %0, 1b" : "+r"(n));
        (void) cm_rollup_accept(root);
    }
}
