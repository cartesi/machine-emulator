#ifndef KECCAK_256_HASHER_H
#define KECCAK_256_HASHER_H

#include <array>
#include <cryptopp/keccak.h>
#include "i-hasher.h"

class keccak_256_hasher final:
    public i_hasher<keccak_256_hasher, CryptoPP::Keccak_256::DIGESTSIZE> {

    CryptoPP::Keccak_256 kc;

friend i_hasher<keccak_256_hasher, CryptoPP::Keccak_256::DIGESTSIZE>;

    void do_begin(void) {
        return kc.Restart();
    }

    void do_add_data(const uint8_t *data, size_t length) {
        return kc.Update(data, length);
    }

    void do_end(digest_type &digest) {
        return kc.Final(digest.data());
    }
};

#endif
