// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

// Compiled only to check that the copies in emulator-constants.h match the emulator.

#include "emulator-constants.h"

#include <cm.h>
#include <machine-reg.hpp>

using cartesi::machine_reg;
using cartesi::machine_reg_address;

static_assert(SHADOW_MCYCLE_ADDRESS == machine_reg_address(machine_reg::mcycle));
static_assert(SHADOW_IFLAGS_Y_ADDRESS == machine_reg_address(machine_reg::iflags_Y));
static_assert(SHADOW_HTIF_TOHOST_ADDRESS == machine_reg_address(machine_reg::htif_tohost));
static_assert(SHADOW_TLB_WRITE_SET == CM_TLB_WRITE);
static_assert(SHADOW_TLB_SET_SIZE == CM_TLB_SET_SIZE);
