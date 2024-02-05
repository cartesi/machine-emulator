// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#ifndef I_DEVICE_STATE_ACCESS
#define I_DEVICE_STATE_ACCESS

#include <cstdint>

namespace cartesi {

/// \file
/// \brief Virtual interface for state access

/// \brief Virtual interface for state access
/// \details \{
/// Memory mapped devices must be able to modify the state.
/// However, the prototype for the read/write callbacks
/// cannot change depending on the different classes implementing the
/// i_state_access interface (which is not virtual).
///
/// Since device access to state is not time critical, the
/// i_device_state_access interface uses virtual methods.  A
/// template class device_state_access implements this
/// virtual interface on top of any class that implements the
/// i_state_access.
/// \}
class i_device_state_access {
public:
    /// \brief Default constructor
    i_device_state_access() = default;

    /// \brief Virtual destructor.
    virtual ~i_device_state_access() = default;

    i_device_state_access(const i_device_state_access &other) = delete;
    i_device_state_access(i_device_state_access &&other) noexcept = delete;
    i_device_state_access &operator=(const i_device_state_access &other) = delete;
    i_device_state_access &operator=(i_device_state_access &&other) noexcept = delete;

    /// \brief Sets bits in mip.
    void set_mip(uint64_t mask) {
        return do_set_mip(mask);
    }

    /// \brief Resets bits in mip.
    void reset_mip(uint64_t mask) {
        return do_reset_mip(mask);
    }

    /// \brief Reads the value of the mip register.
    /// \returns Register value.
    uint64_t read_mip(void) {
        return do_read_mip();
    }

    /// \brief Reads CSR mcycle.
    /// \returns Register value.
    uint64_t read_mcycle(void) {
        return do_read_mcycle();
    }

    /// \brief Sets the iflags_H flag.
    /// \details This is Cartesi-specific.
    void set_iflags_H(void) {
        return do_set_iflags_H();
    }

    /// \brief Sets the iflags_Y flag.
    /// \details This is Cartesi-specific.
    void set_iflags_Y(void) {
        return do_set_iflags_Y();
    }

    /// \brief Sets the iflags_X flag.
    /// \details This is Cartesi-specific.
    void set_iflags_X(void) {
        return do_set_iflags_X();
    }

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
    uint64_t read_clint_mtimecmp(void) {
        return do_read_clint_mtimecmp();
    }

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
    void write_clint_mtimecmp(uint64_t val) {
        return do_write_clint_mtimecmp(val);
    }

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
    uint64_t read_htif_fromhost(void) {
        return do_read_htif_fromhost();
    }

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val) {
        return do_write_htif_fromhost(val);
    }

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
    uint64_t read_htif_tohost(void) {
        return do_read_htif_tohost();
    }

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val) {
        return do_write_htif_tohost(val);
    }

    /// \brief Reads HTIF's ihalt.
    /// \returns Register value.
    uint64_t read_htif_ihalt(void) {
        return do_read_htif_ihalt();
    }

    /// \brief Reads HTIF's iconsole.
    /// \returns Register value.
    uint64_t read_htif_iconsole(void) {
        return do_read_htif_iconsole();
    }

    /// \brief Reads HTIF's yield.
    /// \returns Register value.
    uint64_t read_htif_iyield(void) {
        return do_read_htif_iyield();
    }

    // LCOV_EXCL_START
    /// \brief Writes a chunk of data to a memory PMA range.
    /// \param paddr Target physical address. Must be aligned to data size.
    /// \param data Pointer to chunk of data.
    /// \param log2_size Log 2 of data size. Must be >= 3 and < 64.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range. The search for the PMA range is implicit, and not logged.
    void write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_size) {
        return do_write_memory(paddr, data, log2_size);
    }
    // LCOV_EXCL_STOP

    /// \brief Reads the istart field of a PMA entry
    /// \param p Index of PMA
    uint64_t read_pma_istart(int p) {
        return do_read_pma_istart(p);
    }

    /// \brief Reads the ilength field of a PMA entry
    /// \param p Index of PMA
    uint64_t read_pma_ilength(int p) {
        return do_read_pma_ilength(p);
    }

private:
    virtual void do_set_mip(uint64_t mask) = 0;
    virtual void do_reset_mip(uint64_t mask) = 0;
    virtual uint64_t do_read_mip(void) = 0;
    virtual uint64_t do_read_mcycle(void) = 0;
    virtual void do_set_iflags_H(void) = 0;
    virtual void do_set_iflags_Y(void) = 0;
    virtual void do_set_iflags_X(void) = 0;
    virtual uint64_t do_read_clint_mtimecmp(void) = 0;
    virtual void do_write_clint_mtimecmp(uint64_t val) = 0;
    virtual uint64_t do_read_htif_fromhost(void) = 0;
    virtual void do_write_htif_fromhost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_tohost(void) = 0;
    virtual void do_write_htif_tohost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_ihalt(void) = 0;
    virtual uint64_t do_read_htif_iconsole(void) = 0;
    virtual uint64_t do_read_htif_iyield(void) = 0;
    virtual void do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t log2_size) = 0;
    virtual uint64_t do_read_pma_istart(int p) = 0;
    virtual uint64_t do_read_pma_ilength(int p) = 0;
};

} // namespace cartesi

#endif
