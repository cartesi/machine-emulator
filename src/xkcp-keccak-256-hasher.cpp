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

#include "xkcp-keccak-256-hasher.h"
#include <stdexcept>

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_MULTIVERSIONING)
#define USE_MULTIVERSINING_X86_64
#define GENERIC64_ATTRIBUTE __attribute__((target("default")))
#define SSSE3_ATTRIBUTE __attribute__((target("ssse3")))
#define AVX_ATTRIBUTE __attribute__((target("avx")))
#define AVX2_ATTRIBUTE __attribute__((target("avx2")))
// #define AVX512_ATTRIBUTE __attribute__((target("arch=skylake-avx512")))
#endif

// clang-format off
// NOLINTBEGIN

extern "C" {

#ifdef USE_MULTIVERSINING_X86_64
// Generic 64
HashReturn generic64_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);
HashReturn generic64_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen);
HashReturn generic64_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval);

// SSSE3
HashReturn SSSE3_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);
HashReturn SSSE3_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen);
HashReturn SSSE3_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval);

// AVX
HashReturn AVX_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);
HashReturn AVX_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen);
HashReturn AVX_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval);

// AVX2
HashReturn AVX2_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);
HashReturn AVX2_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen);
HashReturn AVX2_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval);

// AVX512
// int AVX512_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);
// int AVX512_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen);
// int AVX512_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval);

#endif
}

#ifdef USE_MULTIVERSINING_X86_64

// Generic 64
GENERIC64_ATTRIBUTE static HashReturn XKCP_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix) {
    return generic64_Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
}
GENERIC64_ATTRIBUTE static HashReturn XKCP_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen) {
    return generic64_Keccak_HashUpdate(hashInstance, data, databitlen);
}
GENERIC64_ATTRIBUTE static HashReturn XKCP_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval) {
    return generic64_Keccak_HashFinal(hashInstance, hashval);
}

// SSSE3
SSSE3_ATTRIBUTE static HashReturn XKCP_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix) {
    return SSSE3_Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
}
SSSE3_ATTRIBUTE static HashReturn XKCP_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen) {
    return SSSE3_Keccak_HashUpdate(hashInstance, data, databitlen);
}
SSSE3_ATTRIBUTE static HashReturn XKCP_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval) {
    return SSSE3_Keccak_HashFinal(hashInstance, hashval);
}

// AVX
AVX_ATTRIBUTE static HashReturn XKCP_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix) {
    return AVX_Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
}
AVX_ATTRIBUTE static HashReturn XKCP_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen) {
    return AVX_Keccak_HashUpdate(hashInstance, data, databitlen);
}
AVX_ATTRIBUTE static HashReturn XKCP_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval) {
    return AVX_Keccak_HashFinal(hashInstance, hashval);
}

// AVX2
AVX2_ATTRIBUTE static HashReturn XKCP_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix) {
    return AVX2_Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
}
AVX2_ATTRIBUTE static HashReturn XKCP_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen) {
    return AVX2_Keccak_HashUpdate(hashInstance, data, databitlen);
}
AVX2_ATTRIBUTE static HashReturn XKCP_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval) {
    return AVX2_Keccak_HashFinal(hashInstance, hashval);
}

// AVX512
// AVX512_ATTRIBUTE static HashReturn XKCP_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix) {
//     return AVX512_Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
// }
// AVX512_ATTRIBUTE static HashReturn XKCP_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen) {
//     return AVX512_Keccak_HashUpdate(hashInstance, data, databitlen);
// }
// AVX512_ATTRIBUTE static HashReturn XKCP_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval) {
//     return AVX512_Keccak_HashFinal(hashInstance, hashval);
// }

#else // USE_MULTIVERSINING_X86_64

// Generic 64
static HashReturn XKCP_Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix) {
    return Keccak_HashInitialize(hashInstance, rate, capacity, hashbitlen, delimitedSuffix);
}
static HashReturn XKCP_Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, BitLength databitlen) {
    return Keccak_HashUpdate(hashInstance, data, databitlen);
}
static HashReturn XKCP_Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval) {
    return Keccak_HashFinal(hashInstance, hashval);
}

#endif // USE_MULTIVERSINING_X86_64

// NOLINTEND
// clang-format on

namespace cartesi {

void xkcp_keccak_256_hasher::do_begin(void) {
    // We use the same Keccak-256 as in Ethereum, that is,
    // we don't follow FIPS 202 standard, and use delimited suffix 0x01.
    if (XKCP_Keccak_HashInitialize(&m_instance, 1088, 512, 256, 0x01) != KECCAK_SUCCESS) {
        throw std::runtime_error("Keccak_HashInitialize failed");
    }
    m_started = true;
}

void xkcp_keccak_256_hasher::do_add_data(const unsigned char *data, size_t length) {
    if (!m_started || XKCP_Keccak_HashUpdate(&m_instance, data, length * 8) != KECCAK_SUCCESS) {
        throw std::runtime_error("Keccak_HashUpdate failed");
    }
}

void xkcp_keccak_256_hasher::do_end(hash_type &hash) {
    if (!m_started || XKCP_Keccak_HashFinal(&m_instance, hash.data()) != KECCAK_SUCCESS) {
        throw std::runtime_error("Keccak_HashUpdate failed");
    }
}

} // namespace cartesi
