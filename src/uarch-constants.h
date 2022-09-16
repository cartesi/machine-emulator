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

// Memory addresses with special meaning to the microarchitecture
enum class uarch_ctl_addr : uint64_t {
    putchar = UARCH_PUTCHAR_ADDR_DEF,
    abort = UARCH_ABORT_ADDR_DEF,
    pma_mark_page_dirty = UARCH_PMA_MARK_PAGE_DIRTY
};

// Values written to shadow_csr::brkflag from the microarchitecture to control the state of the interpreter's break flag
enum class uarch_brk_ctl : uint64_t {
    not_set = 1,
    set = 2,
    or_with_mip_mie = 3,
    set_from_all = 4,
    assert_no_brk = 5,
};

} // namespace cartesi

#endif
