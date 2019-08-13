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

#ifndef PMA_DEFINES_H
#define PMA_DEFINES_H

#define PMA_HTIF_START_DEF     0x40008000 ///< HTIF base address (to_host)
#define PMA_RAM_START_DEF      0x80000000 ///< RAM start address
#define PMA_ROM_LENGTH_DEF     0xF000 ///< ROM length in bytes
#define PMA_ROM_START_DEF      0x1000 ///< ROM start address
#define PMA_START_DEF          0x800 ///< PMA array start address
#define PMA_EXT_LENGTH_DEF     0x1000 ///< PMA Extension max length in bytes
#define PMA_EXT_START_DEF      (PMA_ROM_START_DEF + PMA_ROM_LENGTH_DEF - PMA_EXT_LENGTH_DEF) ///< PMA extension start address

// helper for using UINT64_C with defines
#define EXPAND_UINT64_C(a) UINT64_C(a)

#endif /* end of include guard: PMA_DEFINES_H */
