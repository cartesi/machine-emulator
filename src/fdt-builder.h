// Copyright 2023 Cartesi Pte. Ltd.
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

#ifndef FDT_BUILDER_H
#define FDT_BUILDER_H

#include <algorithm>
#include <array>
#include <cstdint>
#include <ios>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace cartesi {

enum FDT_constants : uint32_t { FDT_MAGIC = 0xd00dfeed, FDT_VERSION = 17, FDT_COMP_VERSION = 16 };

enum FDT_tokens : uint32_t {
    FDT_BEGIN_NODE = 1, // Marks the beginning of a node’s representation
    FDT_END_NODE = 2,   // Marks the end of a node’s representation
    FDT_PROP = 3,       // Marks the beginning of the representation of one property in the devicetree
    FDT_NOP = 4,        // Ignored by any program parsing the device tree
    FDT_END = 9         // Marks the end of the structure block
};

struct fdt_header {
    uint32_t magic;             // The value 0xd00dfeed (big-endian)
    uint32_t totalsize;         // Total size in bytes of the devicetree data structure.
    uint32_t off_dt_struct;     // Offset in bytes of the structure block from the beginning of the header.
    uint32_t off_dt_strings;    // Offset in bytes of the strings block from the beginning of the header.
    uint32_t off_mem_rsvmap;    // Offset in bytes of the memory reservation block from the beginning of the header.
    uint32_t version;           // Version of the devicetree data structure.
    uint32_t last_comp_version; // Lowest version of the devicetree data structure with which the version used is
                                // backwards compatible.
    uint32_t boot_cpuid_phys;   // Physical ID of the system’s boot CPU.
    uint32_t size_dt_strings;   // Length in bytes of the strings block section of the devicetree blob.
    uint32_t size_dt_struct;    // Length in bytes of the structure block section of the devicetree blob.
};

struct fdt_reserve_entry {
    uint64_t address; // Physical address of a reserved memory region
    uint64_t size;    // Size in bytes of a reserved memory region
};

static inline uint32_t to_be32(uint32_t v) {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");
    return __builtin_bswap32(v);
}

///\brief Helper class for building binary flattened device trees.
class FDTBuilder {
    int32_t open_node_count = 0;
    std::vector<uint32_t> dt_struct;
    std::ostringstream dt_strings;
    std::unordered_map<std::string, uint32_t> dt_strings_map;

    void put_u32(uint32_t v) {
        dt_struct.push_back(to_be32(v));
    }

    void put_data(const uint8_t *data, uint32_t data_len) {
        if (data_len == 0) {
            return;
        }
        // The data is padded with zeros, making sure dt_struct is always 4-byte aligned
        const uint32_t pos = dt_struct.size();
        const uint32_t num_words = (data_len + 3) / 4; // align forward 4-bytes and divide by 4
        dt_struct.resize(pos + num_words, 0);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::copy_n(data, data_len, reinterpret_cast<uint8_t *>(&dt_struct[pos]));
    }

    void put_string(const std::string &s) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        put_data(reinterpret_cast<const uint8_t *>(s.c_str()), s.length() + 1);
    }

public:
    uint32_t get_string_offset(const std::string &name) {
        const auto it = dt_strings_map.find(name);
        if (it != dt_strings_map.end()) {
            return it->second;
        }
        const uint32_t off = dt_strings.tellp();
        dt_strings << name << '\0';
        dt_strings_map.emplace(name, off);
        return off;
    }

    uint32_t get_struct_offset() {
        return dt_struct.size() * sizeof(uint32_t);
    }

    void begin() {
        open_node_count = 0;
        dt_struct.clear();
        dt_strings.clear();
        dt_strings_map.clear();
    }

    void end() {
        if (open_node_count != 0) {
            throw std::runtime_error{"a node was left open in FDT"};
        }
        put_u32(FDT_END);
    }

    void begin_node(const std::string &name) {
        put_u32(FDT_BEGIN_NODE);
        put_string(name);
        open_node_count++;
    }

    void begin_node_num(const std::string &name, uint64_t n) {
        put_u32(FDT_BEGIN_NODE);
        std::ostringstream ss;
        ss << name << "@" << std::hex << n;
        put_string(ss.str());
        open_node_count++;
    }

    void end_node() {
        put_u32(FDT_END_NODE);
        open_node_count--;
    }

    void prop(const std::string &name, const uint8_t *data, uint32_t data_len) {
        put_u32(FDT_PROP);
        put_u32(data_len);
        put_u32(get_string_offset(name));
        put_data(data, data_len);
    }

    void prop_empty(const std::string &name) {
        put_u32(FDT_PROP);
        put_u32(0);
        put_u32(get_string_offset(name));
    }

    void prop_string(const std::string &name, const std::string &v) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        prop(name, reinterpret_cast<const uint8_t *>(v.c_str()), v.length() + 1);
    }

    template <uint32_t N>
    void prop_u32_list(const std::string &name, const std::array<uint32_t, N> &vs) {
        put_u32(FDT_PROP);
        put_u32(vs.size() * sizeof(uint32_t));
        put_u32(get_string_offset(name));
        for (const uint32_t v : vs) {
            put_u32(v);
        }
    }

    template <uint32_t N>
    void prop_u64_list(const std::string &name, const std::array<uint64_t, N> &vs) {
        put_u32(FDT_PROP);
        put_u32(vs.size() * sizeof(uint64_t));
        put_u32(get_string_offset(name));
        for (const uint64_t v : vs) {
            put_u32(static_cast<uint32_t>(v >> 32));
            put_u32(static_cast<uint32_t>(v));
        }
    }

    void prop_u32(const std::string &name, uint32_t v) {
        prop_u32_list<1>(name, {v});
    }

    void prop_u64(const std::string &name, uint64_t v) {
        prop_u64_list<1>(name, {v});
    }

    void finish(unsigned char *buf, uint32_t buf_len) {
        uint32_t off = 0;
        // Initialize header
        const uint32_t header_start = 0;
        fdt_header header{};
        header.magic = to_be32(FDT_MAGIC);
        header.version = to_be32(FDT_VERSION);
        header.last_comp_version = to_be32(FDT_COMP_VERSION);
        header.boot_cpuid_phys = to_be32(0);
        off += sizeof(fdt_header);
        // DT struct
        const uint32_t dt_struct_off = off;
        const uint32_t dt_struct_size = dt_struct.size() * sizeof(uint32_t);
        header.off_dt_struct = to_be32(dt_struct_off);
        header.size_dt_struct = to_be32(dt_struct_size);
        off += dt_struct_size;
        off = (off + 7) & ~7; // align forward 8-bytes
        // DT strings
        const std::string dt_string = dt_strings.str();
        const uint32_t dt_strings_off = off;
        const uint32_t dt_strings_size = dt_string.length();
        header.off_dt_strings = to_be32(dt_strings_off);
        header.size_dt_strings = to_be32(dt_strings_size);
        off += dt_strings_size;
        off = (off + 7) & ~7; // align forward 8-bytes
        // Reserve entry
        const uint32_t reserved_off = off;
        fdt_reserve_entry reserved{};
        reserved.address = to_be32(0);
        reserved.size = to_be32(0);
        header.off_mem_rsvmap = to_be32(off);
        off += sizeof(fdt_reserve_entry);
        off = (off + 7) & ~7; // align forward 8-bytes
        // Finish header
        header.totalsize = to_be32(off);
        // Copy memory
        if (off > buf_len) {
            throw std::runtime_error{"not enough space to store FDT"};
        }
        std::fill_n(buf, buf_len, 0);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::copy_n(reinterpret_cast<const uint8_t *>(&header), sizeof(fdt_header), buf + header_start);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::copy_n(reinterpret_cast<const uint8_t *>(&reserved), sizeof(fdt_reserve_entry), buf + reserved_off);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::copy_n(reinterpret_cast<const uint8_t *>(dt_struct.data()), dt_struct_size, buf + dt_struct_off);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::copy_n(reinterpret_cast<const uint8_t *>(dt_string.data()), dt_strings_size, buf + dt_strings_off);
    }
};

} // namespace cartesi

#endif
