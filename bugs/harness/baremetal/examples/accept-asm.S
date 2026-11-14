/* Assembly-only rollup guest (no runtime, no stack): writes the empty outputs root (precomputed, see
 * README) to the tx buffer and yields manual RX_ACCEPTED (length 32) forever. Build: build.sh examples/accept-asm.S */
#include <address-range-defines.h>
#include <htif-defines.h>
    .section .text.init
    .global _start
_start:
    li t0, AR_CMIO_TX_BUFFER_START_DEF
    la t1, empty_root
    li t2, 4
1:  ld t3, 0(t1)
    sd t3, 0(t0)
    addi t0, t0, 8
    addi t1, t1, 8
    addi t2, t2, -1
    bnez t2, 1b
    /* tohost = yield(dev 2) manual(cmd 1) reason RX_ACCEPTED(1) data 32 */
    li t1, (HTIF_DEV_YIELD_DEF << 56) | (HTIF_YIELD_CMD_MANUAL_DEF << 48) | (HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF << 32) | 32
    li t0, AR_HTIF_START_DEF
2:  sd zero, 8(t0)
    sd t1, 0(t0)
    j 2b
    .section .rodata
    .align 3
empty_root: /* keccak256 outputs tree of height 63, no leaves */
    .byte 0x0a,0x16,0x29,0x46,0xe5,0x61,0x58,0xba,0xc0,0x67,0x3e,0x6d,0xd3,0xbd,0xfd,0xc1
    .byte 0xe4,0xa0,0xe7,0x74,0x4a,0x12,0x0f,0xdb,0x64,0x00,0x50,0xc8,0xd7,0xab,0xe1,0xc6
