#ifndef CRYPTOPP_KECCAK_256_HASHER_H
#define CRYPTOPP_KECCAK_256_HASHER_H

#include <cryptopp/keccak.h>
#include "i-hasher.h"

namespace cartesi {

class cryptopp_keccak_256_hasher final:
    public i_hasher<cryptopp_keccak_256_hasher,
        CryptoPP::Keccak_256::DIGESTSIZE> {

    CryptoPP::Keccak_256 kc{};

    /// \brief No copy constructor
    cryptopp_keccak_256_hasher(const cryptopp_keccak_256_hasher &) = delete;
    /// \brief No move constructor
    cryptopp_keccak_256_hasher(cryptopp_keccak_256_hasher &&) = delete;
    /// \brief No copy assignment
    cryptopp_keccak_256_hasher& operator=(const cryptopp_keccak_256_hasher &) = delete;
    /// \brief No move assignment
    cryptopp_keccak_256_hasher& operator=(cryptopp_keccak_256_hasher &&) = delete;

friend i_hasher<cryptopp_keccak_256_hasher, CryptoPP::Keccak_256::DIGESTSIZE>;

    void do_begin(void) {
        return kc.Restart();
    }

    void do_add_data(const unsigned char *data, size_t length) {
        return kc.Update(data, length);
    }

    void do_end(hash_type &hash) {
        return kc.Final(hash.data());
    }

public:
    /// \brief Default constructor
    cryptopp_keccak_256_hasher(void) = default;
};

} // namespace cartesi

#endif
