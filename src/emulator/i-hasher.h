#ifndef I_HASHER_H
#define I_HASHER_H

/// \file
/// \brief Hasher interface

#include <cstdint>
#include <array>

/// \class
/// \brief Hasher interface.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \tparam DIGEST_SIZE Size of hash.
template <typename DERIVED, int DIGEST_SIZE> class i_hasher { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:

    using digest_type = std::array<uint8_t, DIGEST_SIZE>;

    void begin(void) {
        return derived().do_begin();
    }

    void add_data(const uint8_t *data, size_t length) {
        return derived().do_add_data(data, length);
    }

    void end(digest_type &digest) {
        return derived().do_end(digest);
    }

};

#endif
