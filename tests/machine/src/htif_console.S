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

// This program Exercises HTIF console getchar and putchar.

// @a0 - getchar()
// @a1 - enabled:0, disabled:-1
#define check_console_getchar(x) \
    li t0, x; \
    or t0, t0, a1; \
    bne t0, a0, ack_failed;

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    // Set the exception handler to trap
    // This is just in case an exception happens
    la t0, trap;
    csrw mtvec, t0;

    jal is_console_getchar_enabled;
    add a1, a0, -1;

    call wait_0x400; /* wait for IO to start working */

    // Test console getchar
    htif_console_getchar();
    check_console_getchar('C');

    htif_console_getchar();
    check_console_getchar('T');

    htif_console_getchar();
    check_console_getchar('S');

    htif_console_getchar();
    check_console_getchar('I');

    // Test console putchar
    htif_console_putchar('C');
    htif_console_putchar('T');
    htif_console_putchar('S');
    htif_console_putchar('I');

    htif_exit(42);


wait_0x400:
    li a0, 0x400;
wait:
    addi a0, a0, -1;
    bne zero, a0, wait;
    ret

is_console_getchar_enabled:
    li t0, AR_HTIF_START_DEF; \
    ld t0, O_ICONSOLE (t0); \
    srli t0, t0, HTIF_CONSOLE_CMD_GETCHAR_DEF; \
    andi a0, t0, 1;
    ret

// If HTIF device command is not acked, exit with 2
ack_failed:
    htif_exit(2);

// catch exception and exit
trap:
    htif_exit(1);
