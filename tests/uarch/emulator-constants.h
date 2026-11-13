/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EMULATOR_CONSTANTS_H
#define EMULATOR_CONSTANTS_H

/* Emulator constants for assembly, which cannot include the C++ headers that define them.
 * check-emulator-constants.cpp checks these copies against the emulator. */
#define SHADOW_MCYCLE_ADDRESS 0x100
#define SHADOW_IFLAGS_Y_ADDRESS 0x308
#define SHADOW_HTIF_TOHOST_ADDRESS 0x330
#define SHADOW_TLB_WRITE_SET 2
#define SHADOW_TLB_SET_SIZE 256

#endif
