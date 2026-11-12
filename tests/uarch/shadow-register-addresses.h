/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SHADOW_REGISTER_ADDRESSES_H
#define SHADOW_REGISTER_ADDRESSES_H

/* Shadow register addresses for assembly, which cannot include the C++ headers that define them.
 * check-shadow-register-addresses.cpp checks these copies against the emulator. */
#define SHADOW_MCYCLE_ADDRESS 0x100
#define SHADOW_IFLAGS_Y_ADDRESS 0x308
#define SHADOW_HTIF_TOHOST_ADDRESS 0x330

#endif
