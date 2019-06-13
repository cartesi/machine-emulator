#ifndef I_HASHER_H
#define I_HASHER_H

/// \file
/// \brief Hasher interface

#include <cstdint>
#include <array>

namespace cartesi {

/// \class
/// \brief Hasher interface.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \tparam HASH_SIZE Size of hash.
template <typename DERIVED, int HASH_SIZE> class i_hasher { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:

    constexpr static size_t hash_size = HASH_SIZE;

    using hash_type = std::array<unsigned char, hash_size>;


    void begin(void) {
        return derived().do_begin();
    }

    void add_data(const unsigned char *data, size_t length) {
        return derived().do_add_data(data, length);
    }

    void end(hash_type &hash) {
        return derived().do_end(hash);
    }

};

} // namespace cartesi

#endif
