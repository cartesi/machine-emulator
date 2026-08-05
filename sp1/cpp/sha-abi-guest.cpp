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

// Hashes fixed vectors through the same sha primitives the replay guest uses and
// returns the digests, so the host can compare them against a reference SHA-256.
//
// The precompiles address their buffers as arrays of 8-byte slots holding u32
// values, which the C header does not say. Getting that wrong changes the
// digest, and this guest is what turns that into a failing test instead of a
// wrong root hash surfacing somewhere far away. It links the shipped
// sp1-runtime object unmodified.

#include <cstddef>
#include <cstdint>

extern "C" void read_input(const uint8_t **buf_ptr, size_t *buf_size);
extern "C" void write_output(const uint8_t *output, size_t size);
extern "C" void zk_merkle_tree_hash(uint64_t hash_tree_target, const char *data, unsigned long size, char *hash);
extern "C" void zk_concat_hash(uint64_t hash_tree_target, const char *left, const char *right, char *result);
extern "C" [[noreturn]] void zk_abort_with_msg(const char *msg);
extern "C" void syscall_sha256_extend(uint64_t w[64]);
extern "C" void syscall_sha256_compress(uint64_t w[64], uint64_t state[8]);

namespace {

// Input is a sequence of records: one tag byte, then 32 bytes (leaf) or 64
// bytes (concat). Output is one 32-byte digest per record, in order.
constexpr uint8_t TAG_LEAF = 0;
constexpr uint8_t TAG_CONCAT = 1;
constexpr size_t DIGEST_SIZE = 32;
constexpr size_t MAX_RECORDS = 64;

// The executor addresses w as 64 and state as 8 8-byte slots. If a bump ever
// widens that footprint, the digests can stay plausible while neighboring
// stack is silently smashed — the sentinels bordering the buffers are what
// turn that into an abort.
void check_precompile_footprint() {
    constexpr uint64_t CANARY = 0x5ca1ab1edeadbeef;
    struct {
        uint64_t pre[4];
        uint64_t w[64];
        uint64_t mid[4];
        uint64_t state[8];
        uint64_t post[4];
    } probe = {};
    for (auto &word : probe.pre) {
        word = CANARY;
    }
    for (auto &word : probe.mid) {
        word = CANARY;
    }
    for (auto &word : probe.post) {
        word = CANARY;
    }
    for (size_t i = 0; i < 64; i++) {
        probe.w[i] = i;
    }
    for (size_t i = 0; i < 8; i++) {
        probe.state[i] = i;
    }
    syscall_sha256_extend(probe.w);
    syscall_sha256_compress(probe.w, probe.state);
    for (const auto &word : probe.pre) {
        if (word != CANARY) {
            zk_abort_with_msg("sha-abi-guest: precompile wrote before its buffer");
        }
    }
    for (const auto &word : probe.mid) {
        if (word != CANARY) {
            zk_abort_with_msg("sha-abi-guest: precompile overran w");
        }
    }
    for (const auto &word : probe.post) {
        if (word != CANARY) {
            zk_abort_with_msg("sha-abi-guest: precompile overran state");
        }
    }
}

} // namespace

int main() {
    const uint8_t *input = nullptr;
    size_t input_size = 0;
    read_input(&input, &input_size);
    check_precompile_footprint();

    alignas(8) uint8_t digests[MAX_RECORDS * DIGEST_SIZE];
    size_t produced = 0;
    size_t offset = 0;

    while (offset < input_size) {
        const uint8_t tag = input[offset++];
        const size_t operand_size = (tag == TAG_CONCAT) ? 64 : 32;
        if (tag != TAG_LEAF && tag != TAG_CONCAT) {
            zk_abort_with_msg("sha-abi-guest: unknown record tag");
        }
        if (offset + operand_size > input_size) {
            zk_abort_with_msg("sha-abi-guest: truncated record");
        }
        if (produced == MAX_RECORDS) {
            zk_abort_with_msg("sha-abi-guest: too many records");
        }

        // The operands are copied to an aligned buffer because the precompiles
        // read 8-byte slots, and the input stream is byte-packed.
        alignas(8) uint8_t operand[64];
        for (size_t i = 0; i < operand_size; i++) {
            operand[i] = input[offset + i];
        }
        offset += operand_size;

        char *out = reinterpret_cast<char *>(digests + produced * DIGEST_SIZE);
        if (tag == TAG_CONCAT) {
            zk_concat_hash(1, reinterpret_cast<const char *>(operand), reinterpret_cast<const char *>(operand + 32),
                out);
        } else {
            zk_merkle_tree_hash(1, reinterpret_cast<const char *>(operand), 32, out);
        }
        produced++;
    }

    write_output(digests, produced * DIGEST_SIZE);
    return 0;
}
