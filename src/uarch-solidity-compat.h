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

#ifndef UARCH_INTERPRET_SOLIDITY_COMPAT_H
#define UARCH_INTERPRET_SOLIDITY_COMPAT_H

#include <cassert>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#ifdef DUMP_INSN
#include <cinttypes>
#endif

/// \file
/// \brief Solidity Compatibility Layer
/// \brief The purpose of this file is to facilitate porting the uarch instruction interpreter to Solidity.
/// \brief The uarch interpreter implementation uses functions from this file to perform operations not available
/// \brief or whose behavior differ in Solidity.
/// \brief Arithmetic overflow should never cause exceptions.

namespace cartesi {

// Solidity integer types
using int8 = int8_t;
using uint8 = uint8_t;
using int16 = int16_t;
using uint16 = uint16_t;
using int32 = int32_t;
using uint32 = uint32_t;
using int64 = int64_t;
using uint64 = uint64_t;
using bytes = const unsigned char *;

// Wrapperfunctions used to access data from the uarch state accessor

template <typename UarchState>
static inline uint64 readWord(UarchState &a, uint64 paddr) {
    return a.read_word(paddr);
}

template <typename UarchState>
static inline void writeWord(UarchState &a, uint64 paddr, uint64 val) {
    a.write_word(paddr, val);
}

template <typename UarchState>
static inline uint64 readCycle(UarchState &a) {
    return a.read_cycle();
}

template <typename UarchState>
static inline void writeCycle(UarchState &a, uint64 val) {
    a.write_cycle(val);
}

template <typename UarchState>
static inline uint64 readHaltFlag(UarchState &a) {
    return a.read_halt_flag();
}

template <typename UarchState>
static inline void writeHaltFlag(UarchState &a, uint64 val) {
    a.write_halt_flag(val);
}

template <typename UarchState>
static inline uint64 readPc(UarchState &a) {
    return a.read_pc();
}

template <typename UarchState>
static inline void writePc(UarchState &a, uint64 val) {
    a.write_pc(val);
}

template <typename UarchState>
static inline uint64 readX(UarchState &a, uint8 reg) {
    return a.read_x(reg);
}

template <typename UarchState>
static inline void writeX(UarchState &a, uint8 reg, uint64 val) {
    a.write_x(reg, val);
}

template <typename UarchState>
static inline void resetState(UarchState &a) {
    a.reset_state();
}

template <typename State>
static inline uint64 readIflagsY(State &a) {
    return a.read_iflags_Y();
}

template <typename State>
static inline void writeIflagsY(State &a, uint64 val) {
    a.write_iflags_Y(val);
}

template <typename State>
static inline void writeHtifFromhost(State &a, uint64 val) {
    a.write_htif_fromhost(val);
}

template <typename State>
static inline void writeMemoryWithPadding(State &a, uint64 paddr, bytes data, uint64_t data_length,
    int32 write_length_log2_size) {
    a.write_memory_with_padding(paddr, data, data_length, write_length_log2_size);
}

template <typename UarchState>
static inline void throwRuntimeError(UarchState & /*a*/, const char *message) {
    throw std::runtime_error(message);
}

template <typename UarchState>
static inline void putCharECALL(UarchState &a, uint8 c) {
    a.putchar(c);
}

template <typename UarchState>
static inline void markDirtyPageECALL(UarchState &a, uint64 paddr, uint64 pma_index) {
    a.mark_dirty_page(paddr, pma_index);
}

template <typename UarchState>
static inline void writeTlbECALL(UarchState &a, uint64 set_index, uint64 slot_index, uint64 vaddr_page,
    uint64 vp_offset, uint64 pma_index) {
    a.write_tlb(static_cast<TLB_set_index>(set_index), slot_index, vaddr_page, vp_offset, pma_index);
}

// Conversions and arithmetic functions

static inline int32 uint64ToInt32(uint64 v) {
    return static_cast<int32>(v);
}

static inline uint64 uint64AddInt32(uint64 v, int32 w) {
    return v + w;
}

static inline uint64 uint64SubUint64(uint64 v, uint64 w) {
    return v - w;
}

static inline uint64 uint64AddUint64(uint64 v, uint64 w) {
    return v + w;
}

static inline uint64 uint64ShiftRight(uint64 v, uint32 count) {
    return v >> (count & 0x3f);
}

static inline uint64 uint64ShiftLeft(uint64 v, uint32 count) {
    return v << (count & 0x3f);
}

static inline int64 int64ShiftRight(int64 v, uint32 count) {
    return v >> (count & 0x3f);
}

static inline int64 int64AddInt64(int64 v, int64 w) {
    int64 res = 0;
    __builtin_add_overflow(v, w, &res);
    return res;
}

static inline uint32 uint32ShiftRight(uint32 v, uint32 count) {
    return v >> (count & 0x1f);
}

static inline uint32 uint32ShiftLeft(uint32 v, uint32 count) {
    return v << (count & 0x1f);
}

static inline uint64 int32ToUint64(int32 v) {
    return v;
}

static inline int32 int32ShiftRight(int32 v, uint32 count) {
    return v >> (count & 0x1f);
}

static inline int32 int32AddInt32(int32 v, int32 w) {
    int32 res = 0;
    __builtin_add_overflow(v, w, &res);
    return res;
}

static inline int32 int32SubInt32(int32 v, int32 w) {
    int32 res = 0;
    __builtin_sub_overflow(v, w, &res);
    return res;
}

static inline uint64 int16ToUint64(int16 v) {
    return v;
}

static inline uint64 int8ToUint64(int8 v) {
    return v;
}

static inline uint32 uint32Log2(uint32 v) {
    return 31 - __builtin_clz(v);
}

template <typename T1, typename T2>
void require([[maybe_unused]] T1 condition, [[maybe_unused]] T2 message) {
    assert((condition) && (message));
}

template <typename UarchState>
static void dumpInsn([[maybe_unused]] UarchState &a, [[maybe_unused]] uint64 pc, [[maybe_unused]] uint32 insn,
    [[maybe_unused]] const char *name) {
#ifdef DUMP_INSN
    fprintf(stderr, "%08" PRIx64, pc);
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "%s\n", name);
#endif
}

} // namespace cartesi

#endif
