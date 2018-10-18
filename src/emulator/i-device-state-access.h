#ifndef I_DEVICE_STATE_ACCESS
#define I_DEVICE_STATE_ACCESS

#include <cstdint>

/// \file
/// \brief Device state access interface

/// \class i_device_state_access
/// \brief Interface for machine state access by devices.
/// \details \{
/// Memory mapped devices must be able to modify the state.
/// However, the prototype for the read/write callbacks
/// cannot change depending on the different classes implementing the
/// i_state_access interface (which is not virtual).
///
/// Since device access to state is not time critical, the i_device_state_access
/// interace uses virtual methods.
/// A template class device_state_access implements this virtual interface on top
/// of any class that implements the i_state_access.
/// \}
class i_device_state_access {
public:

    /// \brief Virtual destructor.
    virtual ~i_device_state_access(void) {
        ;
    }

    /// \brief Set bits in mip.
    /// \details See ::processor_set_mip.
    void set_mip(uint32_t mask) {
        return do_set_mip(mask);
    }

    /// \brief Resets bits in mip.
    /// \details See ::processor_reset_mip.
    void reset_mip(uint32_t mask) {
        return do_reset_mip(mask);
    }

    /// \brief Reads the value of the mip register.
    /// \details See ::processor_read_mip.
    uint32_t read_mip(void) {
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

    /// \brief Reads CLINT's mtimecmp.
    /// \returns Register value.
    uint64_t read_mtimecmp(void) {
        return do_read_mtimecmp();
    }

    /// \brief Writes CLINT's mtimecmp.
    /// \param val New register value.
    void write_mtimecmp(uint64_t val) {
        return do_write_mtimecmp(val);
    }

    /// \brief Reads HTIF's fromhost.
    /// \returns Register value.
    uint64_t read_fromhost(void) {
        return do_read_fromhost();
    }

    /// \brief Writes HTIF's fromhost.
    /// \param val New register value.
    void write_fromhost(uint64_t val) {
        return do_write_fromhost(val);
    }

    /// \brief Reads HTIF's tohost.
    /// \returns Register value.
    uint64_t read_tohost(void) {
        return do_read_tohost();
    }

    /// \brief Writes HTIF's tohost.
    /// \param val New register value.
    void write_tohost(uint64_t val) {
        return do_write_tohost(val);
    }

private:

    virtual void do_set_mip(uint32_t mask) = 0;
    virtual void do_reset_mip(uint32_t mask) = 0;
    virtual uint32_t do_read_mip(void) = 0;
    virtual uint64_t do_read_mcycle(void) = 0;
    virtual void do_set_iflags_H(void) = 0;
    virtual uint64_t do_read_mtimecmp(void) = 0;
    virtual void do_write_mtimecmp(uint64_t val) = 0;
    virtual uint64_t do_read_fromhost(void) = 0;
    virtual void do_write_fromhost(uint64_t val) = 0;
    virtual uint64_t do_read_tohost(void) = 0;
    virtual void do_write_tohost(uint64_t val) = 0;
};

#endif
