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

#ifndef UARCH_CONFIG_H
#define UARCH_CONFIG_H

#include <array>
#include <boost/container/static_vector.hpp>
#include <cstdint>
#include <string>

#include "riscv-constants.h"

namespace cartesi {

/// \brief RAM state configuration for the microarchitecture
struct uarch_ram_config final {
    uint64_t length{0};           ///< RAM length
    std::string image_filename{}; ///< RAM image file name
};

/// \brief Microarchitecture processor configuration
struct uarch_processor_config final {
    std::array<uint64_t, UARCH_X_REG_COUNT> x{}; ///< Value of general-purpose registers
    uint64_t pc{UARCH_PC_INIT};                  ///< Value of pc
    uint64_t cycle{UARCH_CYCLE_INIT};            ///< Value of ucycle counter
};

/// \brief Microarchitecture configuration
struct uarch_config final {
    uarch_processor_config processor{}; ///< processor configuration
    uarch_ram_config ram{};             ///< RAM configuration
};

} // namespace cartesi

#endif
