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

#ifndef MACHINE_STATISTICS_H
#define MACHINE_STATISTICS_H

#include <cstdint>

namespace cartesi {

/// \brief Machine statistics
struct machine_statistics {
    uint64_t inner_loop;    ///< Counts executions of inner loop
    uint64_t outer_loop;    ///< Counts executions of outer loop
    uint64_t sv_int;        ///< Counts supervisor interrupts
    uint64_t sv_ex;         ///< Counts supervisor exceptions (except ECALL)
    uint64_t m_int;         ///< Counts machine interrupts
    uint64_t m_ex;          ///< Counts machine exceptions (except ECALL)
    uint64_t atomic_mop;    ///< Counts atomic memory operations
    uint64_t tlb_rhit;      ///< Counts TLB read access hits
    uint64_t tlb_rmiss;     ///< Counts TLB read access misses
    uint64_t tlb_whit;      ///< Counts TLB write access hits
    uint64_t tlb_wmiss;     ///< Counts TLB write access misses
    uint64_t tlb_chit;      ///< Counts TLB code access hits
    uint64_t tlb_cmiss;     ///< Counts TLB code access misses
    uint64_t flush_all;     ///< Counts flush all calls
    uint64_t flush_va;      ///< Counts flush virtual address calls
    uint64_t fence;         ///< Counts fence calls
    uint64_t fence_i;       ///< Counts fence.i calls
    uint64_t fence_vma;     ///< Counts fence.vma calls
    uint64_t priv_level[4]; ///< Counts changes to privilege levels
};

#ifdef DUMP_COUNTERS
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define INC_COUNTER(stats, counter)                                                                                    \
    do {                                                                                                               \
        stats.counter++;                                                                                               \
    } while (0)
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define INC_COUNTER(state, counter)                                                                                    \
    do {                                                                                                               \
    } while (0)
#endif

} // namespace cartesi

#endif
