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

#ifndef UARCH_STATE_H
#define UARCH_STATE_H

/// \file
/// \brief Cartesi microarchitecture machine state structure definition.

#include <cassert>
#include <cstdint>

#include "pma.h"
#include "riscv-constants.h"
#include <boost/container/static_vector.hpp>

namespace cartesi {

struct uarch_state {
    ~uarch_state() {
        ;
    }

    /// \brief No copy or move constructor or assignment
    uarch_state(const uarch_state &other) = delete;
    uarch_state(uarch_state &&other) = delete;
    uarch_state &operator=(const uarch_state &other) = delete;
    uarch_state &operator=(uarch_state &&other) = delete;

    uint64_t pc;                               ///< Program counter.
    std::array<uint64_t, UARCH_X_REG_COUNT> x; ///< Register file.
    uint64_t cycle;                            ///< Cycles counter
    pma_entry rom;                             ///< Memory range for micro ROM
    pma_entry ram;                             ///< Memory range for micro RAM
    pma_entry empty_pma;                       ///< Empty range fallback
};

} // namespace cartesi

#endif
