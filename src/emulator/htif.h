#ifndef HTIF_H
#define HTIF_H

#include <cstdint>
#include <termios.h>

/// \file
/// \brief Host-Target interface device.

// Forward declarations
struct machine_state;

#define HTIF_INTERACT_DIVISOR 10
#define HTIF_CONSOLE_BUF_SIZE 1024

/// \brief Host-Target interface implementation
class htif {

    uint8_t m_buf[HTIF_CONSOLE_BUF_SIZE];  ///< Console buffer.
    ssize_t m_buf_pos;                     ///< Next character in buffer.
    ssize_t m_buf_len;                     ///< Last character in buffer.
    bool m_fromhost_pending;               ///< fromhost is pending.
    machine_state *m_machine;              ///< Associated machine state.
    bool m_interactive;                    ///< Running in interactive mode.
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
    /// \param s Pointer to associated machine state.
    /// \param interactive This is an interactive session with terminal support.
    htif(machine_state *s, bool interactive);

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

    /// \brief Returns associated machine state
    const machine_state *get_machine_state(void) const;

    /// \brief Checks if there is input available from console.
    void poll_console(void);

private:

    /// \brief Initializes console.
    void init_console(void);

    /// \brief Closes console.
    void end_console(void);

};

#endif
