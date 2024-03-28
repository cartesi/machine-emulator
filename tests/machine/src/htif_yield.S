/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "htif_util.h"

// This program Exercises different permutations of HTIF yield:
// manual x automatic, the different 'reasons', and incrementing data values.

// Uses HTIF to exit the emulator with exit code in an immediate.
// HTIF halt device exits with dev = cmd = 0 and a payload with lsb set.
// So the data payload uses bits 1-47
#define exit_imm(imm) \
    li gp, imm; \
    j exit;

// Check HTIF fromhost address for yield command ack
#define check_htif_ack(dev, cmd, data) \
    li t0, PMA_HTIF_START_DEF; \
    ld t3, O_IYIELD (t0); \
    srli t3, t3, cmd; \
    andi t3, t3, 1; \
    addi t3, t3, -1; \
    not t3, t3; /* t3 is all 0 if cmd is disabled, all 1 if enabled */ \
    li t0, dev; \
    slli t1, t0, HTIF_DEV_SHIFT_DEF; \
    li t0, cmd; \
    slli t0, t0, HTIF_CMD_SHIFT_DEF; \
    li t2, HTIF_CMD_MASK_DEF; \
    and t0, t0, t2; \
    or t1, t1, t0; \
    li t0, data; \
    li t2, HTIF_DATA_MASK_DEF; \
    and t0, t0, t2; \
    or t1, t1, t0; \
    and t1, t1, t3; /* if cmd is disabled, expect 0 ack */ \
    li t0, PMA_HTIF_START_DEF; \
    ld t2, O_FROMHOST (t0); \
    bne t1, t2, ack_failed;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    // This is just in case an exception happens
    la t0, trap;
    csrw mtvec, t0;

    // Test yield, manual
    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 10)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);
    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 11)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);
    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 12)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, 13)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);
    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF, 14)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF, 15)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT_DEF, 16)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION_DEF, 17)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_MANUAL_DEF, 0);

    // Test yield, auto
    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 20)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);
    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 21)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);
    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 22)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, 23)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);
    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF, 24)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF, 25)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);

    htif_yield(HTIF_YIELD_CMD_AUTOMATIC_DEF, HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT_DEF, 26)
    check_htif_ack(HTIF_DEV_YIELD_DEF, HTIF_YIELD_CMD_AUTOMATIC_DEF, 0);

    // Test if invalid yields commands is not acked, they are silently ignored
    htif_yield(0xff, HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF, 1)
    bnez a0, trap

    // halt with payload 42
    exit_imm(42);

// If HTIF device command is not acked, exit with 2
ack_failed:
    exit_imm(2);

// catch exception and exit
trap:
    exit_imm(1);

// Exits via HTIF using gp content as the exit code
exit:
    slli gp, gp, 16;
    srli gp, gp, 15;
    ori gp, gp, 1;
1:
    li t0, PMA_HTIF_START_DEF;
    sd x0, O_FROMHOST (t0);
    sd gp, O_TOHOST   (t0);
    j 1b; // unreachable
