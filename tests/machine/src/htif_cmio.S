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

// This test will fetch the cmio buffers from the PMA entries; check that
// `rx_buffer` is filled with a byte patern; then write a byte pattern into
// `tx_buffer`.

/** from: https://www.cartesi.io/en/docs/machine/target/architecture/
 *
 * last entry has length == 0
 *
 * with the following memory layout:
 * +------+--------+--------+------+----+----+---+---+---+---+----+---+
 * |      |        | 63-12  | 11-8 | 7  | 6  | 5 | 4 | 3 | 2 | 1  | 0 |
 * | 0x00 | start  | start  | DID  | IW | IR | X | W | R | E | IO | M |
 * +------+--------+--------+------+----+----+---+---+---+---+----+---+
 * |      |        | 63-11  |                11-0                     |
 * | 0x08 | length | length |             reserved [=0]               |
 * +------+--------+--------+-----------------------------------------+
 */
#define O_START  0x00
#define O_LENGTH 0x08

#define PMA_START_DID_CONST(did) ((did) << 8)
#define PMA_START_DID_MASK    0x0000000000000f00
#define PMA_START_START_MASK  0xfffffffffffff000

.global _start
.align 2;
_start:
    li a2, 0x0123456789abcdef;
    li a0, PMA_START_DID_CONST(PMA_CMIO_RX_BUFFER_DID_DEF);
    jal ra, find_pma_by_did;
    jal ra, check_pma_with_a2;

    li a2, 0x0123456789abcdef;
    li a0, PMA_START_DID_CONST(PMA_CMIO_TX_BUFFER_DID_DEF);
    jal ra, find_pma_by_did;
    jal ra, fill_pma_with_a2;

    htif_exit(0);


/* Find the PMA entry by DID or exit(1)
 *
 * a0: a pma_did_const(x)
 * ret: pointer to pma entry */
find_pma_by_did:
    li t0, PMA_SHADOW_PMAS_START_DEF;
    li t2, PMA_START_DID_MASK;
    /* is the pma array empty? */
    ld t1, O_LENGTH (t0);
    beq t1, zero, not_found;

l0: ld t1, O_START (t0);
    and t1, t1, t2;
    beq t1, a0, found;

    addi t0, t0, 0x10;
    ld t1, O_LENGTH (t0);
    bne t1, zero, l0;
    /* fallthrough */
not_found:
    htif_exit(1);
found:
    mv a0, t0;
    jr ra;


/* a0 -> pma entry pointer */
fill_pma_with_a2:
    ld a1, O_LENGTH(a0);
    ld a0, O_START (a0);
    li t0, PMA_START_START_MASK;
    and a0, a0, t0;
    j memset64; // tail call


/* a0 -> start
 * a1 -> length
 * a2 -> value */
memset64:
    add a1, a0, a1; // a1 = start + length
    bge a0, a1, l2;
l1:
    sd a2, 0 (a0);
    addi a0, a0, 0x08;
    blt a0, a1, l1;
l2: jr ra;


/* a0 -> pma entry pointer */
check_pma_with_a2:
    ld a1, O_LENGTH(a0);
    ld a0, O_START (a0);
    li t0, PMA_START_START_MASK;
    and a0, a0, t0;
    j memcheck64;


/* a0 -> start
 * a1 -> length
 * a2 -> value */
memcheck64:
    add a1, a0, a1; // a1 = start + length
    bge a0, a1, l4;
l3:
    ld a3, 0 (a0);
    bne a3, a2, fail;
    addi a0, a0, 0x08;
    blt a0, a1, l3;
l4: jr ra;
fail:
    htif_exit(1);
