#ifndef HTIF_H
#define HTIF_H

#include <cstdint>
#include <termios.h>

/// \file
/// \brief Host-Target interface device.

// Forward declarations
class machine;

#define HTIF_INTERACT_DIVISOR 10
#define HTIF_CONSOLE_BUF_SIZE 1024

/// \brief Host-Target interface implementation
class htif {

    machine &m_machine;                    ///< Associated machine.
    bool m_interactive;                    ///< Running in interactive mode.
    uint8_t m_buf[HTIF_CONSOLE_BUF_SIZE];  ///< Console buffer.
    ssize_t m_buf_pos;                     ///< Next character in buffer.
    ssize_t m_buf_len;                     ///< Last character in buffer.
    bool m_fromhost_pending;               ///< fromhost is pending.
    int m_divisor_counter;                 ///< Ignored calls to interact.
    int m_old_fd0_flags;                   ///< Saved stdout flags.
    struct termios m_oldtty;               ///< Saved termios values.

public:

    /// \brief Mapping between CSRs and their relative addresses in HTIF memory
    enum class csr {
        tohost   = UINT64_C(0x0),
        fromhost = UINT64_C(0x8)
    };

    /// \brief Obtains the relative address of a CSR in HTIF memory.
    /// \param reg CSR name.
    /// \returns The address.
    static uint64_t get_csr_rel_addr(csr reg);

    /// \brief Constructor
    /// \param s Associated machine.
    /// \param interactive This is an interactive session with terminal support.
    htif(machine &m, bool interactive);

    /// \brief Registers device with the machine
    /// \param start Start address for memory range.
    /// \param length Length of memory range.
    void register_mmio(uint64_t start, uint64_t length);

    /// \brief Interact with the hosts's terminal.
    /// \param htif Pointer to HTIF state
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

private:

    /// \brief Initializes console.
    void init_console(void);

    /// \brief Closes console.
    void end_console(void);

};

#endif
