// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef CRYPTOPP_KECCAK_256_HASHER_H
#define CRYPTOPP_KECCAK_256_HASHER_H

#include <type_traits>
#include <cryptopp/keccak.h>
#include "i-hasher.h"

namespace cartesi {

class cryptopp_keccak_256_hasher final:
    public i_hasher<cryptopp_keccak_256_hasher,
        std::integral_constant<int, CryptoPP::Keccak_256::DIGESTSIZE>> {

    CryptoPP::Keccak_256 kc{};

    /// \brief No copy constructor
    cryptopp_keccak_256_hasher(const cryptopp_keccak_256_hasher &) = delete;
    /// \brief No move constructor
    cryptopp_keccak_256_hasher(cryptopp_keccak_256_hasher &&) = delete;
    /// \brief No copy assignment
    cryptopp_keccak_256_hasher& operator=(const cryptopp_keccak_256_hasher &) = delete;
    /// \brief No move assignment
    cryptopp_keccak_256_hasher& operator=(cryptopp_keccak_256_hasher &&) = delete;

friend i_hasher<cryptopp_keccak_256_hasher, std::integral_constant<int, CryptoPP::Keccak_256::DIGESTSIZE>>;

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

    /// \brief Default destructor
    ~cryptopp_keccak_256_hasher(void) = default;
};

} // namespace cartesi

#endif
