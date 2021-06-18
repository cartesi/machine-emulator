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

#ifndef HTIF_H
#define HTIF_H

#include <cstdint>
#include <termios.h>

#include <htif-defines.h>

#include "machine-config.h"
#include "pma.h"

/// \file
/// \brief Host-Target interface device.

// helper for using UINT64_C with defines
#ifndef EXPAND_UINT64_C
#define EXPAND_UINT64_C(a) UINT64_C(a)
#endif

namespace cartesi {

// Forward declarations
/// \brief HTIF shifts
enum HTIF_shifts {
    HTIF_DEV_SHIFT  = HTIF_DEV_SHIFT_DEF,
    HTIF_CMD_SHIFT  = HTIF_CMD_SHIFT_DEF,
    HTIF_DATA_SHIFT = HTIF_DATA_SHIFT_DEF
};

/// \brief HTIF shifts
enum HTIF_masks: uint64_t {
    HTIF_DEV_MASK = EXPAND_UINT64_C(HTIF_DEV_MASK_DEF),
    HTIF_CMD_MASK = EXPAND_UINT64_C(HTIF_CMD_MASK_DEF),
    HTIF_DATA_MASK = EXPAND_UINT64_C(HTIF_DATA_MASK_DEF)
};

#define HTIF_BUILD(dev, cmd, data) \
    (((static_cast<uint64_t>(dev)  << HTIF_DEV_SHIFT)  & HTIF_DEV_MASK) | \
     ((static_cast<uint64_t>(cmd)  << HTIF_CMD_SHIFT)  & HTIF_CMD_MASK) | \
     ((static_cast<uint64_t>(data) << HTIF_DATA_SHIFT) & HTIF_DATA_MASK))

#define HTIF_DEV_FIELD(reg)  (((reg) & HTIF_DEV_MASK)  >> HTIF_DEV_SHIFT)
#define HTIF_CMD_FIELD(reg)  (((reg) & HTIF_CMD_MASK)  >> HTIF_CMD_SHIFT)
#define HTIF_DATA_FIELD(reg) (((reg) & HTIF_DATA_MASK) >> HTIF_DATA_SHIFT)

#define HTIF_REPLACE_DATA(reg, data) \
    ((static_cast<uint64_t>(reg) & (~HTIF_DATA_MASK)) | \
        (((data) << HTIF_DATA_SHIFT) & HTIF_DATA_MASK))

/// \brief HTIF constants
enum HTIF_constants {
    HTIF_INTERACT_DIVISOR = 10,  ///< Proportion of interacts to ignore
    HTIF_CONSOLE_BUF_SIZE = 1024 ///< Number of characters in console input buffer
};

/// \brief HTIF devices
enum HTIF_devices: uint64_t {
    HTIF_DEVICE_HALT    = HTIF_DEVICE_HALT_DEF,    ///< Used to halt machine
    HTIF_DEVICE_CONSOLE = HTIF_DEVICE_CONSOLE_DEF, ///< Used for console input and output
    HTIF_DEVICE_YIELD   = HTIF_DEVICE_YIELD_DEF,   ///< Used to yield control back to host
};

/// \brief HTIF commands
enum HTIF_commands: uint64_t {
    HTIF_HALT_HALT       = HTIF_HALT_HALT_DEF,
    HTIF_CONSOLE_GETCHAR = HTIF_CONSOLE_GETCHAR_DEF,
    HTIF_CONSOLE_PUTCHAR = HTIF_CONSOLE_PUTCHAR_DEF,
    HTIF_YIELD_PROGRESS  = HTIF_YIELD_PROGRESS_DEF,
    HTIF_YIELD_ROLLUP    = HTIF_YIELD_ROLLUP_DEF,
};

/// \brief Host-Target interface implementation
class htif final {

    bool m_console_getchar;                ///< Provide console getchar.
    char m_buf[HTIF_CONSOLE_BUF_SIZE];     ///< Console buffer.
    ssize_t m_buf_pos;                     ///< Next character in buffer.
    ssize_t m_buf_len;                     ///< Last character in buffer.
    int m_divisor_counter;                 ///< Ignored calls to interact.
    int m_ttyfd;                           ///< The tty file descriptor.
    struct termios m_oldtty;               ///< Saved termios values.

public:

    /// \brief No default constructor
    htif(void) = delete;
    /// \brief No copy constructor
    htif(const htif &) = delete;
    /// \brief No move constructor
    htif(htif &&) = delete;
    /// \brief No copy assignment
    htif &operator=(const htif &) = delete;
    /// \brief No move assignment
    htif &operator=(htif &&) = delete;

    /// \brief Constructor
    /// \param h HTIF device configuration.
    htif(const htif_config &h);

    /// \brief Interact with the hosts's terminal.
    void interact(void);

    /// \brief Destructor
    ~htif();

    /// \brief Checks if there is input available from console.
    void poll_console(void);

    bool console_char_pending(void) const;

    int console_get_char(void);

    /// \brief Mapping between CSRs and their relative addresses in HTIF memory
    enum class csr {
        tohost   = UINT64_C(0x0),
        fromhost = UINT64_C(0x8),
        ihalt     = UINT64_C(0x10),
        iconsole  = UINT64_C(0x18),
        iyield    = UINT64_C(0x20)
    };

    /// \brief Obtains the relative address of a CSR in HTIF memory.
    /// \param reg CSR name.
    /// \returns The address.
    static uint64_t get_csr_rel_addr(csr reg);

    /// \brief Gets the next available console character
    /// \returns The character, or 0 if none are available.
    char console_next_char(void);

private:

    /// \brief Initializes console.
    void init_console(void);

    /// \brief Closes console.
    void end_console(void);

};

/// \brief Creates a PMA entry for the HTIF device
/// \param h HTIF device.
/// \param start Start address for memory range.
/// \param length Length of memory range.
/// \returns Corresponding PMA entry
pma_entry make_htif_pma_entry(htif &h, uint64_t start, uint64_t length);

/// \brief Creates a mock PMA entry for the HTIF device
/// \param start Start address for memory range.
/// \param length Length of memory range.
/// \returns Corresponding PMA entry
pma_entry make_htif_pma_entry(uint64_t start, uint64_t length);

} // namespace cartesi

#endif
