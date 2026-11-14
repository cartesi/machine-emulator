/* Bare-metal guest for R1-R14-1 (no runtime): 3125 iterations of 32 back-to-back HTIF console putchar('\n')
 * stores (100000 characters, about one per mcycle), then halt with exit code 0.
 * Build: $HARNESS/baremetal/build.sh -o guest.bin guest.S */
#include <address-range-defines.h>
#include <htif-defines.h>
    .section .text.init
    .global _start
_start:
    li t0, AR_HTIF_START_DEF
    li t1, (HTIF_DEV_CONSOLE_DEF << 56) | (HTIF_CONSOLE_CMD_PUTCHAR_DEF << 48) | 0x0a
    li t2, 3125
1:
    .rept 32
    sd t1, 0(t0)
    .endr
    addi t2, t2, -1
    bnez t2, 1b
    /* tohost = halt(dev 0) cmd 0, data (0 << 1) | 1 */
    li t1, 1
2:  sd zero, 8(t0)
    sd t1, 0(t0)
    j 2b
