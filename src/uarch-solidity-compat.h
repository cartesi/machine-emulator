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

#ifndef UARCH_INTERPRET_SOLIDITY_COMPAT_H
#define UARCH_INTERPRET_SOLIDITY_COMPAT_H

#include <assert.h>
#include <inttypes.h>

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
static inline bool readHaltFlag(UarchState &a) {
    return a.read_halt_flag();
}

template <typename UarchState>
static inline void setHaltFlag(UarchState &a) {
    return a.set_halt_flag();
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

// Conversions and arithmentic functions

static inline int32 uint64ToInt32(uint64 v) {
    return v;
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

#define require(condition, message) assert((condition) && message)

template <typename UarchState>
static void dumpInsn(UarchState &a, uint64 pc, uint32 insn, const char *name) {
#ifdef DUMP_INSN
    fprintf(stderr, "%08" PRIx64, pc);
    fprintf(stderr, ":   %08" PRIx32 "   ", insn);
    fprintf(stderr, "%s\n", name);
#else
    (void) a;
    (void) insn;
    (void) pc;
    (void) name;
#endif
}

} // namespace cartesi

#endif
