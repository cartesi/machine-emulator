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
    uint64_t read_mip() {
        return do_read_mip();
    }

    /// \brief Reads CSR mcycle.
    /// \returns Register value.
    uint64_t read_mcycle() {
        return do_read_mcycle();
    }

    /// \brief Sets the iflags_H flag.
    /// \details This is Cartesi-specific.
    void set_iflags_H() {
        return do_set_iflags_H();
    }

    /// \brief Sets the iflags_Y flag.
    /// \details This is Cartesi-specific.
    void set_iflags_Y() {
        return do_set_iflags_Y();
    }

    /// \brief Sets the iflags_X flag.
    /// \details This is Cartesi-specific.
    void set_iflags_X() {
        return do_set_iflags_X();
    }

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
    uint64_t read_clint_mtimecmp() {
        return do_read_clint_mtimecmp();
    }

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
    void write_clint_mtimecmp(uint64_t val) {
        return do_write_clint_mtimecmp(val);
    }

    /// \brief Reads PLIC's girqpend.
    /// \returns Register value.
    uint64_t read_plic_girqpend() {
        return do_read_plic_girqpend();
    }

    /// \brief Writes PLIC's girqpend.
    /// \param val New register value.
    void write_plic_girqpend(uint64_t val) {
        return do_write_plic_girqpend(val);
    }

    /// \brief Reads PLIC's girqsrvd.
    /// \returns Register value.
    uint64_t read_plic_girqsrvd() {
        return do_read_plic_girqsrvd();
    }

    /// \brief Writes PLIC's girqsrvd.
    /// \param val New register value.
    void write_plic_girqsrvd(uint64_t val) {
        return do_write_plic_girqsrvd(val);
    }

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
    uint64_t read_htif_fromhost() {
        return do_read_htif_fromhost();
    }

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
    void write_htif_fromhost(uint64_t val) {
        return do_write_htif_fromhost(val);
    }

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
    uint64_t read_htif_tohost() {
        return do_read_htif_tohost();
    }

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
    void write_htif_tohost(uint64_t val) {
        return do_write_htif_tohost(val);
    }

    /// \brief Reads HTIF's ihalt.
    /// \returns Register value.
    uint64_t read_htif_ihalt() {
        return do_read_htif_ihalt();
    }

    /// \brief Reads HTIF's iconsole.
    /// \returns Register value.
    uint64_t read_htif_iconsole() {
        return do_read_htif_iconsole();
    }

    /// \brief Reads HTIF's yield.
    /// \returns Register value.
    uint64_t read_htif_iyield() {
        return do_read_htif_iyield();
    }

    /// \brief Reads a chunk of data from a memory PMA range.
    /// \param address Target physical address.
    /// \param data Receives chunk of memory.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully read, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool read_memory(uint64_t paddr, unsigned char *data, uint64_t length) {
        return do_read_memory(paddr, data, length);
    }

    /// \brief Writes a chunk of data to a memory PMA range.
    /// \param paddr Target physical address.
    /// \param data Pointer to chunk of data.
    /// \param length Size of chunk.
    /// \returns True if PMA was found and memory fully written, false otherwise.
    /// \details The entire chunk of data must fit inside the same memory
    /// PMA range, otherwise it fails. The search for the PMA range is implicit, and not logged.
    bool write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) {
        return do_write_memory(paddr, data, length);
    }

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
    virtual uint64_t do_read_mip() = 0;
    virtual uint64_t do_read_mcycle() = 0;
    virtual void do_set_iflags_H() = 0;
    virtual void do_set_iflags_Y() = 0;
    virtual void do_set_iflags_X() = 0;
    virtual uint64_t do_read_clint_mtimecmp() = 0;
    virtual void do_write_clint_mtimecmp(uint64_t val) = 0;
    virtual uint64_t do_read_plic_girqpend() = 0;
    virtual void do_write_plic_girqpend(uint64_t val) = 0;
    virtual uint64_t do_read_plic_girqsrvd() = 0;
    virtual void do_write_plic_girqsrvd(uint64_t val) = 0;
    virtual uint64_t do_read_htif_fromhost() = 0;
    virtual void do_write_htif_fromhost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_tohost() = 0;
    virtual void do_write_htif_tohost(uint64_t val) = 0;
    virtual uint64_t do_read_htif_ihalt() = 0;
    virtual uint64_t do_read_htif_iconsole() = 0;
    virtual uint64_t do_read_htif_iyield() = 0;
    virtual bool do_read_memory(uint64_t paddr, unsigned char *data, uint64_t length) = 0;
    virtual bool do_write_memory(uint64_t paddr, const unsigned char *data, uint64_t length) = 0;
    virtual uint64_t do_read_pma_istart(int p) = 0;
    virtual uint64_t do_read_pma_ilength(int p) = 0;
};

} // namespace cartesi

#endif
