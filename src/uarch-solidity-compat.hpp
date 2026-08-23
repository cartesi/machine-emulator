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

#ifndef UARCH_SOLIDITY_COMPAT_HPP
#define UARCH_SOLIDITY_COMPAT_HPP

#include <cstdint>
#include <stdexcept>

#include "address-range-constants.hpp"
#include "htif-constants.hpp"
#include "machine-hash.hpp"
#include "shadow-registers.hpp"
#include "shadow-tlb.hpp"

/// \file
/// \brief Solidity compatibility layer for porting the uarch instruction interpreter to Solidity.
///
/// The uarch interpreter uses these functions for operations that are unavailable or behave differently
/// in Solidity. Arithmetic overflow must never raise exceptions.

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
// Solidity's bytes32. The transpiler leaves the name unchanged, mapping it directly to Solidity's
// native bytes32.
using bytes32 = const_machine_hash_view;

// Wrapper functions used to access data from the uarch state accessor

template <typename UarchState>
static inline uint64 readWord(const UarchState a, uint64 paddr) {
    return a.read_word(paddr);
}

template <typename UarchState>
static inline void writeWord(const UarchState a, uint64 paddr, uint64 val) {
    a.write_word(paddr, val);
}

template <typename UarchState>
static inline uint64 readCycle(const UarchState a) {
    return a.read_uarch_cycle();
}

template <typename UarchState>
static inline void writeCycle(const UarchState a, uint64 val) {
    a.write_uarch_cycle(val);
}

template <typename UarchState>
static inline uint64 readHalt(const UarchState a) {
    return a.read_uarch_halt();
}

template <typename UarchState>
static inline void writeHalt(const UarchState a, uint64 val) {
    a.write_uarch_halt(val);
}

template <typename UarchState>
static inline uint64 readPc(const UarchState a) {
    return a.read_uarch_pc();
}

template <typename UarchState>
static inline void writePc(const UarchState a, uint64 val) {
    a.write_uarch_pc(val);
}

template <typename UarchState>
static inline uint64 readX(const UarchState a, uint8 reg) {
    return a.read_uarch_x(reg);
}

template <typename UarchState>
static inline void writeX(const UarchState a, uint8 reg, uint64 val) {
    a.write_uarch_x(reg, val);
}

template <typename UarchState>
static inline void resetState(const UarchState a) {
    a.reset_uarch();
}

template <typename UarchState>
static inline void revertState(const UarchState a) {
    a.revert_state();
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
static inline uint64 readMcycle(State &a) {
    return a.read_mcycle();
}

template <typename State>
static inline void writeImcyclemax(State &a, uint64 val) {
    a.write_imcyclemax(val);
}

template <typename State>
static inline void writeHtifFromhost(State &a, uint64 val) {
    a.write_htif_fromhost(val);
}

template <typename State>
static inline uint64 readHtifTohost(State &a) {
    return a.read_htif_tohost();
}

// The revert root hash is a 32-byte machine hash stored raw in its dedicated shadow slot. The page
// model hashes the bytes as-is, so the write must produce the same page bytes across all replayers.
static constexpr uint64 REVERT_ROOT_HASH_LENGTH = 32;
static constexpr uint64 REVERT_ROOT_HASH_LOG2_LENGTH = 5;

template <typename State>
static inline void writeRevertRootHash(State &a, bytes32 revertRootHash) {
    // The padded write is already implemented in every replayer; a raw write_memory would
    // be a second bulk-write primitive to implement, test, and keep in lockstep.
    a.write_memory_with_padding(AR_SHADOW_REVERT_ROOT_HASH_START, revertRootHash.data(), REVERT_ROOT_HASH_LENGTH,
        REVERT_ROOT_HASH_LOG2_LENGTH);
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
static inline void putCharECALL(const UarchState a, uint8 c) {
    a.putchar(c);
}

template <typename UarchState>
static inline void writeTlbECALL(const UarchState a, uint64 set_index, uint64 slot_index, uint64 vaddr_page,
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

static inline bool isYieldedManualWith(uint64 tohost, uint64 yieldReason) {
    const uint64 dev = uint64ShiftRight(tohost & HTIF_DEV_MASK, HTIF_DEV_SHIFT);
    const uint64 cmd = uint64ShiftRight(tohost & HTIF_CMD_MASK, HTIF_CMD_SHIFT);
    const uint64 reason = uint64ShiftRight(tohost & HTIF_REASON_MASK, HTIF_REASON_SHIFT);
    return dev == HTIF_DEV_YIELD && cmd == HTIF_YIELD_CMD_MANUAL && reason == yieldReason;
}

// Must reject under every build flag: the transpiled Solidity require always reverts, so this
// cannot be an assert (compiled out under NDEBUG).
template <typename T1, typename T2>
void require(T1 condition, T2 message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename UarchState>
[[maybe_unused]] static auto dumpInsn([[maybe_unused]] const UarchState a, [[maybe_unused]] uint64 pc,
    [[maybe_unused]] uint32 insn, [[maybe_unused]] const char *name) {
#ifdef DUMP_UARCH_INSN
    d_printf("ua %08" PRIx64, pc);
    d_printf(":   %08" PRIx32 "   ", insn);
    d_printf("%s\n", name);
#endif
    return a.make_scoped_note(name);
}

} // namespace cartesi

#endif
