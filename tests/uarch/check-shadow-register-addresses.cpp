// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: Apache-2.0

// Compiled only to check that the copies in shadow-register-addresses.h match the emulator.

#include "shadow-register-addresses.h"

#include <machine-reg.hpp>

using cartesi::machine_reg;
using cartesi::machine_reg_address;

static_assert(SHADOW_MCYCLE_ADDRESS == machine_reg_address(machine_reg::mcycle));
static_assert(SHADOW_IFLAGS_Y_ADDRESS == machine_reg_address(machine_reg::iflags_Y));
static_assert(SHADOW_HTIF_TOHOST_ADDRESS == machine_reg_address(machine_reg::htif_tohost));
