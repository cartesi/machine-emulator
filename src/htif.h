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

/// \file
/// \brief Host-Target interface device.

namespace cartesi {

// Forward declarations
class machine;

/// \brief HTIF constants
enum HTIF_constants {
    HTIF_INTERACT_DIVISOR = 10, ///< Proportion of interacts to ignore
    HTIF_CONSOLE_BUF_SIZE = 1024 ///< Number of characters in console input buffer
};

/// \brief Host-Target interface implementation
class htif final {

    machine &m_machine;                    ///< Associated machine.
    bool m_interactive;                    ///< Running in interactive mode.
    char m_buf[HTIF_CONSOLE_BUF_SIZE];     ///< Console buffer.
    ssize_t m_buf_pos;                     ///< Next character in buffer.
    ssize_t m_buf_len;                     ///< Last character in buffer.
    bool m_fromhost_pending;               ///< fromhost is pending.
    int m_divisor_counter;                 ///< Ignored calls to interact.
    int m_old_fd0_flags;                   ///< Saved stdout flags.
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
    /// \param m Associated machine.
    /// \param interactive This is an interactive session with terminal support.
    /// \details The constructor for the associated machine is typically done yet when the constructor for the HTIF device is invoked.
    htif(machine &m, bool interactive);

    /// \brief Registers device with the machine
    /// \param start Start address for memory range.
    /// \param length Length of memory range.
    void register_mmio(uint64_t start, uint64_t length);

    /// \brief Interact with the hosts's terminal.
    void interact(void);

    /// \brief Destructor
    ~htif();

    /// \brief Resets the fromhost pending flag
    void reset_fromhost_pending(void);

    /// \brief Checks the fromhost pending flag
    bool fromhost_pending(void) const;

    /// \brief Checks the if HTIF is interactive
    bool is_interactive(void) const;

    /// \brief Returns the associated machine
    const machine &get_machine(void) const;

    /// \brief Checks if there is input available from console.
    void poll_console(void);

    /// \brief Mapping between CSRs and their relative addresses in HTIF memory
    enum class csr {
        tohost   = UINT64_C(0x0),
        fromhost = UINT64_C(0x8)
    };

    /// \brief Obtains the relative address of a CSR in HTIF memory.
    /// \param reg CSR name.
    /// \returns The address.
    static uint64_t get_csr_rel_addr(csr reg);

private:

    /// \brief Initializes console.
    void init_console(void);

    /// \brief Closes console.
    void end_console(void);

};

} // namespace cartesi

#endif
