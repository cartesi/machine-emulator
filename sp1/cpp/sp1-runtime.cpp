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

#include <cstddef>
#include <cstring>
#include <stdint.h>

#include "zk-runtime.hpp"

// SP1 runtime primitives from libzkevm.a
extern "C" void syscall_write(uint32_t fd, const uint8_t *buf, size_t nbytes);
extern "C" NO_RETURN void syscall_halt(uint8_t exit_code);
// On the RV64 target the sha256 precompiles address w and state with an 8-byte
// stride: 64 and 8 u64 slots each holding a u32 value (see sp1-core-executor
// minimal/precompiles/sha256). A u32-packed buffer overruns.
extern "C" void syscall_sha256_extend(uint64_t w[64]);
extern "C" void syscall_sha256_compress(uint64_t w[64], uint64_t state[8]);

extern "C" NO_RETURN void zk_abort_with_msg(const char *msg);

extern "C" void __cxa_pure_virtual() {
    zk_abort_with_msg("pure virtual call");
}

extern "C" int atexit([[maybe_unused]] void (*f)()) {
    return 0;
}

void operator delete(void * /*ptr*/) noexcept {}
void operator delete(void * /*ptr*/, size_t /*size*/) noexcept {}

extern "C" void __assert_func(const char * /*file*/, int /*line*/, const char * /*func*/, const char * /*e*/) {
    zk_abort_with_msg("assertion failed");
}

extern "C" void zk_putchar(char character);

extern "C" void _putchar(char character) {
    zk_putchar(character);
}

extern "C" void zk_putchar(char character) {
    syscall_write(1, reinterpret_cast<const uint8_t *>(&character), 1);
}

// abort() itself comes from libzkevm.a; assert() in zk-runtime.hpp calls it.

extern "C" NO_RETURN void zk_abort_with_msg(const char *msg) {
    syscall_write(2, reinterpret_cast<const uint8_t *>(msg), strlen(msg));
    syscall_halt(1);
}

// SHA-256 over SP1's extend/compress precompile syscalls, bypassing libzkevm's
// zkvm_sha256 wrapper (whose per-call software overhead dominates page hashing).
// Only the sizes the word tree produces exist here: 32-byte leaves and 64-byte
// concatenations, so a full block never coexists with padding bookkeeping.

static inline uint32_t be32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

static void sha256_leaf_or_concat(const uint8_t *data, unsigned long size, uint8_t *hash) {
    uint64_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19};
    uint64_t w[64];
    if (size == 64) {
        for (int i = 0; i < 16; i++) {
            w[i] = be32(data + 4 * i);
        }
        syscall_sha256_extend(w);
        syscall_sha256_compress(w, state);
        // padding-only block: 0x80, zeros, 64-bit bit length (512)
        w[0] = 0x80000000;
        for (int i = 1; i < 15; i++) {
            w[i] = 0;
        }
        w[15] = 512;
        syscall_sha256_extend(w);
        syscall_sha256_compress(w, state);
    } else if (size == 32) {
        for (int i = 0; i < 8; i++) {
            w[i] = be32(data + 4 * i);
        }
        w[8] = 0x80000000;
        for (int i = 9; i < 15; i++) {
            w[i] = 0;
        }
        w[15] = 256;
        syscall_sha256_extend(w);
        syscall_sha256_compress(w, state);
    } else {
        zk_abort_with_msg("sha256_leaf_or_concat: unsupported size");
    }
    for (int i = 0; i < 8; i++) {
        hash[4 * i] = static_cast<uint8_t>(state[i] >> 24);
        hash[4 * i + 1] = static_cast<uint8_t>(state[i] >> 16);
        hash[4 * i + 2] = static_cast<uint8_t>(state[i] >> 8);
        hash[4 * i + 3] = static_cast<uint8_t>(state[i]);
    }
}

// The zk_* hash primitives reproduce the host word-tree exactly.
// hash_tree_target 1 selects SHA-256, the only target the zk guests support.

extern "C" void zk_concat_hash(uint64_t hash_tree_target, const char *left, const char *right, char *result) {
    if (hash_tree_target != 1) {
        zk_abort_with_msg("zk_concat_hash: hash_tree_target must be 1");
    }
    alignas(8) uint8_t conctd[64];
    memcpy(conctd, left, 32);
    memcpy(conctd + 32, right, 32);
    sha256_leaf_or_concat(conctd, 64, reinterpret_cast<uint8_t *>(result));
}

extern "C" void zk_merkle_tree_hash(uint64_t hash_tree_target, const char *data, unsigned long size, char *hash) {
    if (hash_tree_target != 1) {
        zk_abort_with_msg("zk_merkle_tree_hash: hash_tree_target must be 1");
    }
    if (size > 32) {
        // The halving recursion assumes power-of-two sizes (as every caller passes); an odd
        // size would silently drop its last byte.
        if ((size & (size - 1)) != 0) {
            zk_abort_with_msg("zk_merkle_tree_hash: size must be a power of two");
        }
        const unsigned long half_size = size / 2;
        char left_hash[32];
        zk_merkle_tree_hash(hash_tree_target, data, half_size, left_hash);
        char right_hash[32];
        zk_merkle_tree_hash(hash_tree_target, data + half_size, half_size, right_hash);
        zk_concat_hash(hash_tree_target, left_hash, right_hash, hash);
    } else {
        sha256_leaf_or_concat(reinterpret_cast<const uint8_t *>(data), size, reinterpret_cast<uint8_t *>(hash));
    }
}
