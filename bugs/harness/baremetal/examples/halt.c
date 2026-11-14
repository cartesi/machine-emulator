/* Halts immediately with exit code 42 (iflags_H set, htif_tohost data = (42 << 1) | 1). */
#include "cm-baremetal.h"
int main(void) {
    cm_puts("halt example\n");
    return 42;
}
