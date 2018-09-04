#ifndef I_DEVICE_STATE_ACCESS
#define I_DEVICE_STATE_ACCESS

/// \file
/// \brief Device state access interface

/// \class i_device_state_access
/// \details Memory mapped devices must be able to modify the state.
/// However, the prototype for the read/write callbacks
/// cannot change depending on the different classes implementing the
/// i_state_access interface (which is not virtual).
///
/// Since device access to state is not time critical, the i_device_state_access
/// interace uses virtual methods.
/// A template class device_state_access implements this virtual interface on top
/// of any class that implements the i_state_access.
class i_device_state_access {
public:

    virtual ~i_device_state_access(void) {
        ;
    }

    void set_mip(uint32_t mask) {
        return do_set_mip(mask);
    }

    void reset_mip(uint32_t mask) {
        return do_reset_mip(mask);
    }

    uint32_t read_mip(void) {
        return do_read_mip();
    }

    uint64_t read_mcycle(void) {
        return do_read_mcycle();
    }

    void set_iflags_H(void) {
        return do_set_iflags_H();
    }

    uint64_t read_mtimecmp(void) {
        return do_read_mtimecmp();
    }

    void write_mtimecmp(uint64_t val) {
        return do_write_mtimecmp(val);
    }

    uint64_t read_fromhost(void) {
        return do_read_fromhost();
    }

    void write_fromhost(uint64_t val) {
        return do_write_fromhost(val);
    }

    uint64_t read_tohost(void) {
        return do_read_tohost();
    }

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
