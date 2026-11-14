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

// This program stores the doubleword in a1 at the address in a0 and yields manually, so the host acts while the
// store's page is recorded as dirty only by its write TLB slot. When resumed, it flushes the TLB and halts.

// Section with code
.section .text.init
.align 2;
.global _start;
_start:
    sd a1, 0(a0);
    htif_yield(HTIF_YIELD_CMD_MANUAL_DEF, HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF, 0);
    sfence.vma;
    htif_exit(0);
