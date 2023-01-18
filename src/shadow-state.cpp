// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include <cinttypes>

#include "i-device-state-access.h"
#include "pma-constants.h"
#include "pma-driver.h"
#include "riscv-constants.h"
#include "shadow-state.h"
#include "strict-aliasing.h"

namespace cartesi {

static constexpr uint64_t uarch_ram_length_abs_addr = shadow_state_get_csr_abs_addr(shadow_state_csr::uarch_ram_length);

extern "C" const uint64_t shadow_state_uarch_ram_length_abs_addr = uarch_ram_length_abs_addr;

const pma_driver shadow_state_driver = {"SHADOW STATE", device_read_error, device_write_error};

} // namespace cartesi
