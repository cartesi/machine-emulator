/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic bare-metal CMIO guest for the portable computation-hash suite.
 */

#include <address-range-defines.h>
#include <htif-defines.h>
#include "htif_util.h"

#define ACTION_ACCEPT       0
#define ACTION_REJECT       1
#define ACTION_EXCEPTION    2
#define ACTION_HALT         3
#define ACTION_MANUAL_OTHER 4

.section .text.init
.align 2
.global _start
_start:
    /* Rolling-template boundary. */
    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, 0)

read_command:
    li s0, AR_CMIO_RX_BUFFER_START_DEF
    lw t0, 0(s0)
    li t1, 0x31544843              /* "CHT1", little endian */
    bne t0, t1, bad_command
    lbu s1, 4(s0)                 /* action */
    lbu s4, 5(s0)                 /* automatic output count */
    lhu s5, 6(s0)                 /* manual-other reason */
    ld s2, 8(s0)                  /* requested terminal mcycle */
    ld s6, 16(s0)                 /* action payload */

1:  beqz s4, 2f
    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF, 8)
    addi s4, s4, -1
    j 1b

2:  li t0, ACTION_ACCEPT
    beq s1, t0, action_accept
    li t0, ACTION_REJECT
    beq s1, t0, action_reject
    li t0, ACTION_EXCEPTION
    beq s1, t0, action_exception
    li t0, ACTION_HALT
    beq s1, t0, action_halt
    li t0, ACTION_MANUAL_OTHER
    beq s1, t0, action_manual_other
    j bad_command

action_accept:
    li s3, htif_const(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF,
        htif_yield_const(HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, 32))
    j wait_for_terminal_cycle
action_reject:
    li s3, htif_const(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF,
        htif_yield_const(HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF, 0))
    j wait_for_terminal_cycle
action_exception:
    slli t0, s6, 24
    srli t0, t0, 24
    li s3, htif_const(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF,
        htif_yield_const(HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION_DEF, 0))
    or s3, s3, t0
    j wait_for_terminal_cycle
action_halt:
    slli s3, s6, 1
    ori s3, s3, 1
    j wait_for_terminal_cycle
action_manual_other:
    slli t0, s5, 32
    slli t1, s6, 32
    srli t1, t1, 32
    or t0, t0, t1
    li s3, htif_const(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0)
    or s3, s3, t0

/*
 * Stay well outside the final straight-line tail while waiting.  Once close,
 * jump backwards from terminal_store into a NOP sled.  The fixed jump setup
 * plus the selected suffix makes the store
 * retire at exactly s2.  create-computation-hash-corpus.lua probes every
 * boundary fixture and rejects the artifact if this invariant changes.
 */
wait_for_terminal_cycle:
    csrr t0, mcycle
    sub t1, s2, t0
    li t2, 96
    bltu t2, t1, wait_for_terminal_cycle
    csrr t0, mcycle
    sub t0, s2, t0
    addi t0, t0, -11
    slli t0, t0, 2
    la t1, terminal_store
    sub t1, t1, t0
    jalr zero, t1, 0

    .rept 96
    nop
    .endr
terminal_store:
    li t0, AR_HTIF_START_DEF
    sd zero, O_FROMHOST(t0)
    sd s3, O_TOHOST(t0)
    j read_command

bad_command:
    htif_exit(127)
1:  j 1b
