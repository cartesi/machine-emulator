/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CUSTOM_PRISTINE_HALT_H
#define CUSTOM_PRISTINE_HALT_H

#include <htif-defines.h>

#include "riscv_test.h"
#include "shadow-register-addresses.h"

/* Instructions that custom_pristine_halt executes outside its padding and countdown loop, counting the
 * halting ecall */
#define CUSTOM_PRISTINE_HALT_FIXED_CYCLES 23

/* Pristine uarch program for the collector tests. Each run is one mcycle of a stub machine that rejects
 * every input. At a manual yield, which is a fixed point, the run changes nothing. Otherwise it advances
 * mcycle and leaves the machine at a manual yield that rejects the input. Either way, the halting ecall
 * executes as uarch cycle halt_cycle, because no branch other than the countdown loop's depends on the
 * machine state. */
.macro custom_pristine_halt halt_cycle
    /* t0 = iflags_Y, which is 1 at a manual yield and 0 otherwise */
    ld t0, SHADOW_IFLAGS_Y_ADDRESS(zero)
    /* mcycle += 1 - iflags_Y */
    ld t1, SHADOW_MCYCLE_ADDRESS(zero)
    addi t1, t1, 1
    sub t1, t1, t0
    sd t1, SHADOW_MCYCLE_ADDRESS(zero)
    /* t2 = tohost of a manual yield that rejects the input */
    addi t2, zero, HTIF_DEV_YIELD_DEF
    slli t2, t2, HTIF_DEV_SHIFT_DEF - HTIF_CMD_SHIFT_DEF
    ori t2, t2, HTIF_YIELD_CMD_MANUAL_DEF
    slli t2, t2, HTIF_CMD_SHIFT_DEF - HTIF_REASON_SHIFT_DEF
    ori t2, t2, HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF
    slli t2, t2, HTIF_REASON_SHIFT_DEF
    /* tohost = iflags_Y ? tohost : t2, selected with the mask iflags_Y - 1 */
    ld t3, SHADOW_HTIF_TOHOST_ADDRESS(zero)
    addi t4, t0, -1
    xor t2, t2, t3
    and t2, t2, t4
    xor t2, t2, t3
    sd t2, SHADOW_HTIF_TOHOST_ADDRESS(zero)
    /* iflags_Y = 1 */
    addi t0, zero, 1
    sd t0, SHADOW_IFLAGS_Y_ADDRESS(zero)
    /* Pad and count down so the halting ecall executes as uarch cycle halt_cycle */
    .rept (\halt_cycle - CUSTOM_PRISTINE_HALT_FIXED_CYCLES) % 2
    nop
    .endr
    lui t5, %hi((\halt_cycle - CUSTOM_PRISTINE_HALT_FIXED_CYCLES) / 2)
    addiw t5, t5, %lo((\halt_cycle - CUSTOM_PRISTINE_HALT_FIXED_CYCLES) / 2)
1:  addi t5, t5, -1
    bnez t5, 1b
    RVTEST_HALT
.endm

#endif
