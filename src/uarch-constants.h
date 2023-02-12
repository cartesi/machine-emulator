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

#ifndef UARCH_CONSTANTS_H
#define UARCH_CONSTANTS_H

#include <cstdint>
#include <uarch-defines.h>

namespace cartesi {

/// \brief Memory addresses with special meaning to the microarchitecture
enum class uarch_mmio_address : uint64_t {
    halt = UARCH_MMIO_HALT_ADDR_DEF,       ///< Write to this address to halt the micro machine
    putchar = UARCH_MMIO_PUTCHAR_ADDR_DEF, ///< Write to this address for printing characters to the console
    abort = UARCH_MMIO_ABORT_ADDR_DEF,     ///< Write to this address to abort execution of the micro machine
};

/// \briefThe value that halts the micro machine when written to uarch_mmio_address::halt
const uint64_t uarch_mmio_halt_value = UARCH_MMIO_HALT_VALUE_DEF;

/// \briefThe value that aborts the micro machine execution written to uarch_mmio_address::abort
const uint64_t uarch_mmio_abort_value = UARCH_MMIO_ABORT_VALUE_DEF;

} // namespace cartesi

#endif
