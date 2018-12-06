#ifndef KECCAK_256_HASHER_H
#define KECCAK_256_HASHER_H

#include <array>
#include <cryptopp/keccak.h>
#include "i-hasher.h"

namespace cartesi {

class keccak_256_hasher final:
    public i_hasher<keccak_256_hasher, CryptoPP::Keccak_256::DIGESTSIZE> {

    CryptoPP::Keccak_256 kc{};

    /// \brief No copy constructor
    keccak_256_hasher(const keccak_256_hasher &) = delete;
    /// \brief No move constructor
    keccak_256_hasher(keccak_256_hasher &&) = delete;
    /// \brief No copy assignment
    keccak_256_hasher& operator=(const keccak_256_hasher &) = delete;
    /// \brief No move assignment
    keccak_256_hasher& operator=(keccak_256_hasher &&) = delete;

friend i_hasher<keccak_256_hasher, CryptoPP::Keccak_256::DIGESTSIZE>;

    void do_begin(void) {
        return kc.Restart();
    }

    void do_add_data(const uint8_t *data, size_t length) {
        return kc.Update(data, length);
    }

    void do_end(hash_type &hash) {
        return kc.Final(hash.data());
    }

public:
    /// \brief Default constructor
    keccak_256_hasher(void) = default;
};

} // namespace cartesi

#endif
