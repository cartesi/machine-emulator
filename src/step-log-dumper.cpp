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

#include <cstdint>
#include <span>
#include <string>

#include "address-range-constants.hpp"
#include "hex.hpp"
#include "machine.hpp"
#include "step-log-dumper.hpp"

namespace cartesi {

// The revert root hash slot is a hash, not a register, so get_address_name does not name it
static std::string address_name(uint64_t paddr) {
    if (paddr >= AR_SHADOW_REVERT_ROOT_HASH_START && paddr - AR_SHADOW_REVERT_ROOT_HASH_START < sizeof(machine_hash)) {
        return "revert_root_hash";
    }
    return machine::get_address_name(paddr);
}

void step_log_dumper::read(const char *name, uint64_t paddr, uint64_t val) {
    if (m_muted) {
        return;
    }
    line() << "read " << (name != nullptr ? name : address_name(paddr)) << "@0x" << std::hex << paddr << ": 0x" << val
           << std::dec << '(' << val << ")\n";
}

void step_log_dumper::write(const char *name, uint64_t paddr, uint64_t old_val, uint64_t new_val) {
    if (m_muted) {
        return;
    }
    line() << "write " << (name != nullptr ? name : address_name(paddr)) << "@0x" << std::hex << paddr << ": 0x"
           << old_val << std::dec << '(' << old_val << ") -> 0x" << std::hex << new_val << std::dec << '(' << new_val
           << ")\n";
}

// Same shapes the JSON access log printer used for big writes: abbreviated hashes, and the first and
// last three bytes of data, followed by the size
static std::string abbreviated(const_machine_hash_view hash) {
    return encode_hex(hash).substr(0, 10);
}

static std::string snippet(std::span<const unsigned char> bytes) {
    if (bytes.size() <= 6) {
        return encode_hex(bytes);
    }
    return encode_hex(bytes.first(3)) + "..." + encode_hex(bytes.last(3));
}

void step_log_dumper::write_hash(const char *name, uint64_t paddr, int log2_size, const_machine_hash_view old_hash,
    const_machine_hash_view new_hash, std::span<const unsigned char> data) {
    if (m_muted) {
        return;
    }
    line() << "write " << (name != nullptr ? name : address_name(paddr)) << "@0x" << std::hex << paddr << std::dec
           << ": hash:\"" << abbreviated(old_hash) << "\"(2^" << log2_size << " bytes) -> hash:\""
           << abbreviated(new_hash) << "\"" << (data.empty() ? "" : " " + snippet(data)) << "(2^" << log2_size
           << " bytes)\n";
}

void step_log_dumper::write_bytes(const char *name, uint64_t paddr, int log2_size,
    std::span<const unsigned char> old_bytes, std::span<const unsigned char> new_bytes) {
    if (m_muted) {
        return;
    }
    line() << "write " << (name != nullptr ? name : address_name(paddr)) << "@0x" << std::hex << paddr << std::dec
           << ": " << snippet(old_bytes) << "(2^" << log2_size << " bytes) -> " << snippet(new_bytes) << "(2^"
           << log2_size << " bytes)\n";
}

void step_log_dumper::revert(const_machine_hash_view root_hash) {
    if (m_muted) {
        return;
    }
    line() << "revert to root hash " << encode_hex(root_hash) << '\n';
}

} // namespace cartesi
