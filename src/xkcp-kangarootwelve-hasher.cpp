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

#include "xkcp-kangarootwelve-hasher.h"
#include <stdexcept>

#if defined(__GNUC__) && defined(__x86_64__) && !defined(NO_MULTIVERSIONING)
#define USE_MULTIVERSINING_X86_64
#define GENERIC64_ATTRIBUTE __attribute__((target("default")))
#define SSSE3_ATTRIBUTE __attribute__((target("ssse3")))
#define AVX_ATTRIBUTE __attribute__((target("avx")))
#define AVX2_ATTRIBUTE __attribute__((target("avx2")))
#define AVX512_ATTRIBUTE __attribute__((target("avx512f")))
#else
#define GENERIC64_ATTRIBUTE
#endif

// clang-format off
// NOLINTBEGIN

extern "C" {

// Generic 64
int generic64_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen);
int generic64_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen);
int generic64_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen);

#ifdef USE_MULTIVERSINING_X86_64
// SSSE3
int SSSE3_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen);
int SSSE3_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen);
int SSSE3_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen);

// AVX
int AVX_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen);
int AVX_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen);
int AVX_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen);

// AVX2
int AVX2_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen);
int AVX2_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen);
int AVX2_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen);

// AVX512
int AVX512_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen);
int AVX512_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen);
int AVX512_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen);
#endif
}

// Generic 64
GENERIC64_ATTRIBUTE static int XKCP_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen) {
    return generic64_KangarooTwelve_Initialize(hashInstance, outputByteLen);
}
GENERIC64_ATTRIBUTE static int XKCP_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen) {
    return generic64_KangarooTwelve_Update(hashInstance, input, inputByteLen);
}
GENERIC64_ATTRIBUTE static int XKCP_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen) {
    return generic64_KangarooTwelve_Final(hashInstance, output, customization, customByteLen);
}

#ifdef USE_MULTIVERSINING_X86_64

// SSSE3
SSSE3_ATTRIBUTE static int XKCP_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen) {
    return SSSE3_KangarooTwelve_Initialize(hashInstance, outputByteLen);
}
SSSE3_ATTRIBUTE static int XKCP_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen) {
    return SSSE3_KangarooTwelve_Update(hashInstance, input, inputByteLen);
}
SSSE3_ATTRIBUTE static int XKCP_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen) {
    return SSSE3_KangarooTwelve_Final(hashInstance, output, customization, customByteLen);
}

// AVX
AVX_ATTRIBUTE static int XKCP_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen) {
    return AVX_KangarooTwelve_Initialize(hashInstance, outputByteLen);
}
AVX_ATTRIBUTE static int XKCP_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen) {
    return AVX_KangarooTwelve_Update(hashInstance, input, inputByteLen);
}
AVX_ATTRIBUTE static int XKCP_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen) {
    return AVX_KangarooTwelve_Final(hashInstance, output, customization, customByteLen);
}

// AVX2
AVX2_ATTRIBUTE static int XKCP_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen) {
    return AVX2_KangarooTwelve_Initialize(hashInstance, outputByteLen);
}
AVX2_ATTRIBUTE static int XKCP_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen) {
    return AVX2_KangarooTwelve_Update(hashInstance, input, inputByteLen);
}
AVX2_ATTRIBUTE static int XKCP_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen) {
    return AVX2_KangarooTwelve_Final(hashInstance, output, customization, customByteLen);
}

// AVX512
AVX512_ATTRIBUTE static int XKCP_KangarooTwelve_Initialize(KangarooTwelve_Instance *hashInstance, size_t outputByteLen) {
    return AVX512_KangarooTwelve_Initialize(hashInstance, outputByteLen);
}
AVX512_ATTRIBUTE static int XKCP_KangarooTwelve_Update(KangarooTwelve_Instance *hashInstance, const unsigned char *input, size_t inputByteLen) {
    return AVX512_KangarooTwelve_Update(hashInstance, input, inputByteLen);
}
AVX512_ATTRIBUTE static int XKCP_KangarooTwelve_Final(KangarooTwelve_Instance *hashInstance, unsigned char *output, const unsigned char *customization, size_t customByteLen) {
    return AVX512_KangarooTwelve_Final(hashInstance, output, customization, customByteLen);
}

#endif // USE_MULTIVERSINING_X86_64

// NOLINTEND
// clang-format on

namespace cartesi {

#define K12_SUCCESS 0

#define XKCP_KangarooTwelve_Initialize generic64_KangarooTwelve_Initialize
#define XKCP_KangarooTwelve_Update generic64_KangarooTwelve_Update
#define XKCP_KangarooTwelve_Final generic64_KangarooTwelve_Final

void xkcp_kangarootwelve_hasher::do_begin(void) {
    if (XKCP_KangarooTwelve_Initialize(&m_instance, 32) != K12_SUCCESS) {
        throw std::runtime_error("KangarooTwelve_Initialize failed");
    }
    m_started = true;
}

void xkcp_kangarootwelve_hasher::do_add_data(const unsigned char *data, size_t length) {
    if (!m_started || XKCP_KangarooTwelve_Update(&m_instance, data, length) != K12_SUCCESS) {
        throw std::runtime_error("KangarooTwelve_Update failed");
    }
}

void xkcp_kangarootwelve_hasher::do_end(hash_type &hash) {
    if (!m_started || XKCP_KangarooTwelve_Final(&m_instance, hash.data(), nullptr, 0) != K12_SUCCESS) {
        throw std::runtime_error("KangarooTwelve_Final failed");
    }
}

} // namespace cartesi
